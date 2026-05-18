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
    ) -> str:
        """
        Save model with version and integrity signature.
        Returns version string.
        """
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
            "metadata": metadata or {},
            "file_size_bytes": len(model_bytes),
        }
        (model_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

        # Update "latest" symlink
        latest_link = self.base_dir / name / "latest"
        if latest_link.exists():
            latest_link.unlink()
        latest_link.symlink_to(version)

        logger.info(
            "Model saved",
            name=name,
            version=version,
            hash=content_hash[:16],
            size=len(model_bytes),
        )
        return version

    def load_model(self, name: str, version: str = "latest") -> xgb.Booster:
        """
        Load model from the store with integrity verification.
        Raises SecurityError if signature doesn't match.
        """
        if version == "latest":
            version_dir = (self.base_dir / name / "latest").resolve()
        else:
            version_dir = self.base_dir / name / version
        return self._load_verified(version_dir / "model.json", version_dir / "manifest.json",
                                    name=name, version=version)

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
            model_path    = path / "model.json"
            manifest_path = path / "manifest.json"
            return self._load_verified(model_path, manifest_path,
                                        name=path.parent.name, version=path.name)

        if not path.exists():
            raise FileNotFoundError(f"Model not found: {model_ref}")

        # File path — check for sibling manifest
        manifest_path = path.parent / "manifest.json"
        if manifest_path.exists():
            return self._load_verified(path, manifest_path,
                                        name=path.parent.parent.name,
                                        version=path.parent.name)

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
            raise FileNotFoundError(f"Model not found: {name}/{version} at {model_path}")
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
                name=name, version=version,
                expected=manifest["content_hash"][:16], actual=actual_hash[:16],
            )
            raise SecurityError(
                f"Model file tampered: expected hash "
                f"{manifest['content_hash'][:16]}…, got {actual_hash[:16]}…"
            )

        expected_sig = self._sign(actual_hash)
        if not hmac_compare(expected_sig, manifest["signature"]):
            logger.critical("MODEL SIGNATURE INVALID", name=name, version=version)
            raise SecurityError(f"Model signature verification failed for {name}/{version}")

        model = xgb.Booster()
        model.load_model(str(model_path))
        logger.info("Model loaded and verified", name=name, version=version,
                    hash=actual_hash[:16])
        return model

    def rollback(self, name: str, to_version: str) -> None:
        """Roll back to a previous model version."""
        version_dir = self.base_dir / name / to_version
        if not version_dir.exists():
            raise FileNotFoundError(f"Version {to_version} not found for {name}")

        latest_link = self.base_dir / name / "latest"
        if latest_link.exists():
            latest_link.unlink()
        latest_link.symlink_to(to_version)
        logger.warning("Model rolled back", name=name, to_version=to_version)

    def list_versions(self, name: str) -> list[dict]:
        """List all versions of a model with metadata."""
        model_dir = self.base_dir / name
        versions = []
        for d in sorted(model_dir.iterdir()):
            if d.is_dir() and d.name.startswith("v"):
                manifest_path = d / "manifest.json"
                if manifest_path.exists():
                    versions.append(json.loads(manifest_path.read_text()))
        return versions

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
