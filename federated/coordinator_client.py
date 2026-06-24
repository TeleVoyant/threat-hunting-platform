# federated/coordinator_client.py
"""
Org-side REST client to the apt-fl-coordinator.

Drives this org's half of a federated round against the standalone coordinator:
discover open rounds, (optionally) verify the coordinator-signed round
announcement, submit a DP-noised + Ed25519-signed contribution, and fetch +
verify the coordinator-signed global model.

It reads the coordinator URL + mTLS material + the org keypair from LocalFLState
(configured by the operator after enrollment) and uses federated.attestation —
the SAME canonical-JSON + Ed25519 crypto the coordinator verifies against.

Transport: a real requests.Session with mTLS (client cert + key + CA pin) in
production. Tests inject a session-like object (e.g. a FastAPI TestClient) via
`session=`; auth then uses the bootstrap X-FL-API-Key header, which the
coordinator accepts as an org-identity fallback unless FL_REQUIRE_MTLS is set.
"""

import base64
import hashlib
import json
import os
import tempfile
from typing import Callable, Optional

from federated.attestation import (
    build_contribution_attestation, build_leave_request_attestation,
)
from shared.logging import get_logger

logger = get_logger("federated.coordinator_client")


class CoordinatorClient:
    def __init__(
        self,
        *,
        base_url: str,
        org_id: str,
        sign_fn: Callable[[bytes], bytes],        # LocalFLState.sign_attestation
        verify_fn: Callable[[bytes, bytes], bool],  # LocalFLState.verify_coordinator_signature
        api_key: Optional[str] = None,
        client_cert_pem: Optional[str] = None,
        client_key_pem: Optional[str] = None,
        ca_cert_pem: Optional[str] = None,
        session=None,
        timeout: float = 30.0,
    ):
        self.org_id = org_id
        self.sign_fn = sign_fn
        self.verify_fn = verify_fn
        self.timeout = timeout
        self._tmp: list[str] = []
        self._headers: dict[str, str] = {}
        if api_key:
            self._headers["X-FL-API-Key"] = api_key

        if session is not None:
            # Injected (tests): relative paths resolve against the TestClient base.
            self._s = session
            self._base = ""
        else:
            import requests
            self._s = requests.Session()
            self._base = base_url.rstrip("/")
            if client_cert_pem and client_key_pem:
                self._s.cert = (self._tmpfile(client_cert_pem),
                                self._tmpfile(client_key_pem))   # mTLS client identity
            if ca_cert_pem:
                self._s.verify = self._tmpfile(ca_cert_pem)      # pin the federation CA

    # ── transport helpers ───────────────────────────────────────────────────

    def _tmpfile(self, pem) -> str:
        fd, p = tempfile.mkstemp(suffix=".pem")
        os.write(fd, pem.encode() if isinstance(pem, str) else pem)
        os.close(fd)
        self._tmp.append(p)
        return p

    def close(self) -> None:
        for p in self._tmp:
            try:
                os.unlink(p)
            except OSError:
                pass
        self._tmp.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _get(self, path: str) -> dict:
        r = self._s.get(self._base + path, headers=self._headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    # ── round flow ───────────────────────────────────────────────────────────

    def list_active_rounds(self) -> list[dict]:
        """Open rounds this org is invited to (round discovery)."""
        return self._get("/fl/rounds/active").get("active_rounds", [])

    def verify_announcement(self, round_id: int) -> dict:
        """Fetch + verify the coordinator-signed round announcement. Raises if the
        signature doesn't verify against the configured coordinator public key."""
        pl = self._get(f"/fl/rounds/{round_id}/announcement")
        ok = self.verify_fn(pl["signed_attestation"].encode("utf-8"),
                            bytes.fromhex(pl["signature_hex"]))
        if not ok:
            raise ValueError(f"round {round_id} announcement signature INVALID")
        return json.loads(pl["signed_attestation"])

    def submit_contribution(self, round_id: int, model_bytes: bytes,
                            num_examples: int) -> dict:
        """One-shot challenge -> signed attestation -> multipart upload. The
        attestation binds sha256(model) + org + round + challenge, so a MITM
        cannot swap the model without breaking signature verification."""
        challenge = self._get(f"/fl/rounds/{round_id}/challenge")["challenge"]
        att = build_contribution_attestation(
            round_id=round_id, org_id=self.org_id, model_bytes=model_bytes,
            num_examples=num_examples, challenge=challenge)
        sig = self.sign_fn(att)
        r = self._s.post(
            self._base + f"/fl/rounds/{round_id}/contribute",
            data={"attestation": att.decode("utf-8"), "signature": sig.hex()},
            files={"model": ("model.json", model_bytes, "application/json")},
            headers=self._headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def fetch_global_model(self) -> dict:
        """Download the current ACTIVE global model and verify the coordinator's
        Ed25519 signature AND sha256(model) before returning the bytes. Raises on
        any verification failure — never return a model the org shouldn't trust."""
        pl = self._get("/fl/global-model")
        model_bytes = base64.b64decode(pl["model_b64"])
        att_bytes = pl["signed_attestation"].encode("utf-8")
        if not self.verify_fn(att_bytes, bytes.fromhex(pl["signature_hex"])):
            raise ValueError("global model coordinator signature INVALID")
        att = json.loads(att_bytes)
        if att.get("model_sha256") != hashlib.sha256(model_bytes).hexdigest():
            raise ValueError("global model sha256 does not match signed attestation")
        return {
            "round_id":   pl.get("round_id"),
            "version_id": pl.get("version_id"),
            "model_bytes": model_bytes,
        }

    # ── Mutual-ack removal (org self-removal handshake) ──────────────────────

    def request_leave(self, reason: str = "") -> dict:
        """Build + sign fl.leave_request.v1 and POST it. The coordinator verifies
        the signature, moves the org to 'leave_pending', and records the signed
        request (org half of the mutual ack)."""
        att = build_leave_request_attestation(org_id=self.org_id, reason=reason)
        sig = self.sign_fn(att)
        r = self._s.post(
            self._base + f"/fl/orgs/{self.org_id}/leave-request",
            json={"attestation": att.decode("utf-8"), "signature": sig.hex()},
            headers=self._headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_removal_status(self) -> dict:
        """Poll the coordinator for this org's removal status. When approved
        (status 'revoked') the response carries the coordinator-signed
        fl.removal_confirm.v1, which is VERIFIED here before returning
        confirmed=True. Raises if the signature doesn't verify."""
        pl = self._get(f"/fl/orgs/{self.org_id}/removal-status")
        out = {"status": pl.get("status"), "confirmed": False}
        rc = pl.get("removal_confirm")
        if pl.get("status") == "revoked" and rc:
            att_bytes = rc["signed_attestation"].encode("utf-8")
            if not self.verify_fn(att_bytes, bytes.fromhex(rc["signature_hex"])):
                raise ValueError("removal confirmation signature INVALID")
            out["confirmed"] = True
        return out
