# detection/model_store.py
"""
Model store with versioning, integrity signing, and rollback.

Every model file is:
1. Stored with version metadata
2. SHA-256 signed at training time
3. Verified at load time — if signature doesn't match, refuse to load
4. Kept with previous versions for rollback
"""

import hashlib
import hmac as _hmac
import json
import os
import shutil
import time
from pathlib import Path
from typing import Optional

import xgboost as xgb
from shared.logging import get_logger


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string comparison for HMAC verification."""
    return _hmac.compare_digest(a, b)


logger = get_logger("detection.model_store")


class ModelStore:

    def __init__(self, base_dir: str = "detection/models", signing_key: str = ""):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.signing_key = signing_key  # HMAC key for signatures

    def save_model(
        self,
        model: xgb.Booster,
        name: str,
        metadata: dict = None,
        status: str = "active",
    ) -> str:
        """
        Save model with version and integrity signature.
        Returns version string.

        status: "active" (default — production-ready, the latest symlink points
        here) or "staged" (awaits admin promotion via promote() before being
        used by detectors). Auto-retrain writes "staged"; CLI writes "active".
        """
        if status not in ("staged", "active", "archived", "discarded"):
            raise ValueError(f"Invalid status: {status!r}")
        version = f"v{int(time.time())}"
        model_dir = self.base_dir / name / version
        model_dir.mkdir(parents=True, exist_ok=True)

        # Save model file
        model_path = model_dir / "model.json"
        model.save_model(str(model_path))

        # Compute integrity hash
        model_bytes = model_path.read_bytes()
        content_hash = hashlib.sha256(model_bytes).hexdigest()
        signature = self._sign(content_hash)

        # Save manifest
        manifest = {
            "name": name,
            "version": version,
            "created_at": time.time(),
            "content_hash": content_hash,
            "signature": signature,
            "status": status,
            "metadata": metadata or {},
            "file_size_bytes": len(model_bytes),
        }
        (model_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

        # Only advance the "latest" pointer for active versions — staged
        # versions wait for promote() to flip the symlink.
        if status == "active":
            self._set_latest(name, version)

        logger.info(
            "Model saved",
            name=name,
            version=version,
            status=status,
            hash=content_hash[:16],
            size=len(model_bytes),
        )
        return version

    def _set_latest(self, name: str, version: str) -> None:
        latest_link = self.base_dir / name / "latest"
        if latest_link.exists() or latest_link.is_symlink():
            latest_link.unlink()
        latest_link.symlink_to(version)

    def load_model(self, name: str, version: str = "latest") -> xgb.Booster:
        """
        Load model from the store with integrity verification.
        Raises SecurityError if signature doesn't match.
        """
        if version == "latest":
            version_dir = (self.base_dir / name / "latest").resolve()
        else:
            version_dir = self.base_dir / name / version
        return self._load_verified(
            version_dir / "model.json",
            version_dir / "manifest.json",
            name=name,
            version=version,
        )

    def load_from_path(self, model_ref: str) -> xgb.Booster:
        """
        Flexible loader that takes any of:
          - A versioned directory path  (e.g. detection/models/lateral_movement/v123/)
          - A model.json file with a sibling manifest.json (verified)
          - A flat .json model file with NO manifest (loaded with a warning — legacy/dev)

        Production deployments should always have manifests; the legacy path
        is preserved so existing flat models keep working during migration.
        """
        path = Path(model_ref)

        if path.is_dir():
            model_path = path / "model.json"
            manifest_path = path / "manifest.json"
            return self._load_verified(
                model_path, manifest_path, name=path.parent.name, version=path.name
            )

        if not path.exists():
            raise FileNotFoundError(f"Model not found: {model_ref}")

        # File path — check for sibling manifest
        manifest_path = path.parent / "manifest.json"
        if manifest_path.exists():
            return self._load_verified(
                path,
                manifest_path,
                name=path.parent.parent.name,
                version=path.parent.name,
            )

        # Flat file with no manifest — load without verification
        logger.warning(
            "Loading model WITHOUT integrity verification (no sibling manifest)",
            path=str(path),
        )
        model = xgb.Booster()
        model.load_model(str(path))
        return model

    def _load_verified(
        self,
        model_path: Path,
        manifest_path: Path,
        *,
        name: str,
        version: str,
    ) -> xgb.Booster:
        """Shared verification path used by both load_model and load_from_path."""
        if not model_path.exists():
            raise FileNotFoundError(
                f"Model not found: {name}/{version} at {model_path}"
            )
        if not manifest_path.exists():
            raise SecurityError(
                f"Manifest missing for {name}/{version} — refusing to load unverified model"
            )

        manifest = json.loads(manifest_path.read_text())
        model_bytes = model_path.read_bytes()
        actual_hash = hashlib.sha256(model_bytes).hexdigest()

        if actual_hash != manifest["content_hash"]:
            logger.critical(
                "MODEL INTEGRITY VIOLATION",
                name=name,
                version=version,
                expected=manifest["content_hash"][:16],
                actual=actual_hash[:16],
            )
            raise SecurityError(
                f"Model file tampered: expected hash "
                f"{manifest['content_hash'][:16]}…, got {actual_hash[:16]}…"
            )

        expected_sig = self._sign(actual_hash)
        if not hmac_compare(expected_sig, manifest["signature"]):
            logger.critical("MODEL SIGNATURE INVALID", name=name, version=version)
            raise SecurityError(
                f"Model signature verification failed for {name}/{version}"
            )

        # Anonymizer state must match training (gg). Mismatch silently changes
        # per-user feature values at inference.
        meta = manifest.get("metadata", {}) or {}
        trained_anon = meta.get("anonymize")
        runtime_anon = os.environ.get("APT_ANONYMIZE", "1") == "1"
        if trained_anon is not None and bool(trained_anon) != runtime_anon:
            raise SecurityError(
                f"Anonymizer mismatch for {name}/{version}: "
                f"trained={trained_anon} runtime={runtime_anon}"
            )

        model = xgb.Booster()
        model.load_model(str(model_path))

        # Schema pin (t): when feature_names is present in the manifest,
        # the booster's own feature_names must match exactly — otherwise
        # the inference pipeline would silently zero-fill / permute columns.
        trained_feats = meta.get("feature_names")
        if trained_feats:
            booster_feats = model.feature_names or []
            if list(booster_feats) != list(trained_feats):
                raise SecurityError(
                    f"Feature schema drift for {name}/{version}: "
                    f"trained={len(trained_feats)} live={len(booster_feats)}"
                )

        logger.info(
            "Model loaded and verified",
            name=name,
            version=version,
            hash=actual_hash[:16],
            features=len(model.feature_names or []),
        )
        return model

    def rollback(self, name: str, to_version: str) -> None:
        """Roll back to a previous model version (sets it active)."""
        version_dir = self.base_dir / name / to_version
        if not version_dir.exists():
            raise FileNotFoundError(f"Version {to_version} not found for {name}")
        self._update_status(name, to_version, "active")
        self._set_latest(name, to_version)
        logger.warning("Model rolled back", name=name, to_version=to_version)

    def promote(self, name: str, version: str) -> dict:
        """Mark a staged version as the new active one.

        Flips the named version's manifest status to "active", archives the
        previously-active version (so list_versions still surfaces it for
        rollback), and updates the "latest" symlink. Returns the new manifest.
        Used by the admin promotion endpoint after reviewing a staged build's
        evaluation report.
        """
        version_dir = self.base_dir / name / version
        if not version_dir.exists():
            raise FileNotFoundError(f"Version {version} not found for {name}")
        # Demote prior active (if any) → archived
        for v in self.list_versions(name):
            if v.get("status") == "active" and v["version"] != version:
                self._update_status(name, v["version"], "archived")
        # Promote the target
        new_manifest = self._update_status(name, version, "active")
        self._set_latest(name, version)
        logger.info("Model promoted", name=name, version=version)
        return new_manifest

    def _update_status(self, name: str, version: str, status: str) -> dict:
        if status not in ("staged", "active", "archived", "discarded"):
            raise ValueError(f"Invalid status: {status!r}")
        manifest_path = self.base_dir / name / version / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"Manifest missing for {name}/{version}")
        manifest = json.loads(manifest_path.read_text())
        manifest["status"] = status
        manifest_path.write_text(json.dumps(manifest, indent=2))
        return manifest

    def discard(self, name: str, version: str) -> dict:
        """Flip a staged version's status to 'discarded'.

        Operator-driven action: the staged model was reviewed and rejected
        (eval metrics didn't pass NFR-02, looked overfit, drift wasn't
        meaningful, etc.). Files stay on disk so the operator can still
        inspect them or undo via a future un-discard; permanent removal
        is a separate `delete()` call.

        Refuses to discard an active or archived version (those have a
        deliberate lifecycle path: rollback for archived, promote a
        replacement before archiving an active). Only `staged` can be
        discarded; trying anything else raises ValueError.
        """
        current = self._load_manifest(name, version)
        if current.get("status") != "staged":
            raise ValueError(
                f"Cannot discard {name}/{version}: status is "
                f"{current.get('status', 'unknown')!r}, only 'staged' can be discarded"
            )
        new_manifest = self._update_status(name, version, "discarded")
        logger.info("Model discarded", name=name, version=version)
        return new_manifest

    def delete(self, name: str, version: str) -> None:
        """Permanently remove a version's directory from disk.

        Only allowed for 'discarded' or 'archived' versions. NEVER for
        'active' (would brick detection) or 'staged' (operator hasn't
        decided yet -- discard first, then delete from the discarded list).
        Raises ValueError if status doesn't permit deletion, FileNotFoundError
        if the directory's already gone.
        """
        import shutil

        current = self._load_manifest(name, version)
        status = current.get("status", "unknown")
        if status not in ("discarded", "archived"):
            raise ValueError(
                f"Cannot delete {name}/{version}: status is {status!r}, "
                f"only 'discarded' or 'archived' versions can be permanently deleted"
            )
        version_dir = self.base_dir / name / version
        if not version_dir.exists():
            raise FileNotFoundError(f"{name}/{version} directory already gone")
        # rmtree the version dir. The "latest" symlink shouldn't point here
        # because that would mean status=active, which we already rejected.
        shutil.rmtree(version_dir)
        logger.warning("Model version permanently deleted",
                       name=name, version=version, was_status=status)

    def _load_manifest(self, name: str, version: str) -> dict:
        """Helper: load + return a version's manifest dict, or raise."""
        manifest_path = self.base_dir / name / version / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"Manifest missing for {name}/{version}")
        return json.loads(manifest_path.read_text())

    def list_versions(self, name: str) -> list[dict]:
        """List all versions of a model with metadata.

        Sorted oldest-first. Adds an implicit `status="active"` to legacy
        manifests so callers written against the new field still work, and
        sanitises any NaN/Infinity floats (left behind by old training runs
        where the eval set had only one class) so the dict is JSON-safe for
        the dashboard.
        """
        import math

        def _clean(v):
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                return None
            if isinstance(v, dict):
                return {k: _clean(x) for k, x in v.items()}
            if isinstance(v, list):
                return [_clean(x) for x in v]
            return v

        model_dir = self.base_dir / name
        versions = []
        if not model_dir.exists():
            return versions
        for d in sorted(model_dir.iterdir()):
            if d.is_dir() and d.name.startswith("v"):
                manifest_path = d / "manifest.json"
                if manifest_path.exists():
                    # parse_constant lets us survive non-standard NaN/Infinity
                    # tokens written by older json.dumps invocations.
                    m = json.loads(
                        manifest_path.read_text(), parse_constant=lambda c: None
                    )
                    m = _clean(m)
                    m.setdefault("status", "active")
                    versions.append(m)
        return versions

    def list_staged(self, name: str) -> list[dict]:
        """Staged versions only -- the admin promotion queue."""
        return [v for v in self.list_versions(name) if v.get("status") == "staged"]

    def list_discarded(self, name: str) -> list[dict]:
        """Discarded versions only -- the admin permanently-delete queue."""
        return [v for v in self.list_versions(name) if v.get("status") == "discarded"]

    def _sign(self, content_hash: str) -> str:
        """HMAC signature of the content hash."""
        import hmac

        return hmac.new(
            self.signing_key.encode(),
            content_hash.encode(),
            hashlib.sha256,
        ).hexdigest()


class SecurityError(Exception):
    pass
