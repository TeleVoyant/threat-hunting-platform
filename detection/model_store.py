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
import json
import shutil
import time
from pathlib import Path
from typing import Optional

import xgboost as xgb
from shared.logging import get_logger

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
        Load model with integrity verification.
        Raises SecurityError if signature doesn't match.
        """
        if version == "latest":
            version_dir = (self.base_dir / name / "latest").resolve()
        else:
            version_dir = self.base_dir / name / version

        model_path = version_dir / "model.json"
        manifest_path = version_dir / "manifest.json"

        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {name}/{version}")

        # ── INTEGRITY CHECK ──
        manifest = json.loads(manifest_path.read_text())
        model_bytes = model_path.read_bytes()
        actual_hash = hashlib.sha256(model_bytes).hexdigest()

        if actual_hash != manifest["content_hash"]:
            logger.critical(
                "MODEL INTEGRITY VIOLATION",
                name=name,
                version=version,
                expected_hash=manifest["content_hash"][:16],
                actual_hash=actual_hash[:16],
            )
            raise SecurityError(
                f"Model file has been tampered with! "
                f"Expected hash {manifest['content_hash'][:16]}..., "
                f"got {actual_hash[:16]}..."
            )

        expected_sig = self._sign(actual_hash)
        if expected_sig != manifest["signature"]:
            logger.critical("MODEL SIGNATURE INVALID", name=name, version=version)
            raise SecurityError(
                f"Model signature verification failed for {name}/{version}"
            )

        # ── LOAD ──
        model = xgb.Booster()
        model.load_model(str(model_path))
        logger.info("Model loaded and verified", name=name, version=version)
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
