# federated/participation.py
"""
Org-side federated participation service.

Orchestrates this org's role in a round, reusing the platform's existing model
lifecycle so the federated model behaves like any other detector version:

  contribute()   load the ACTIVE detector model (detection/models/<det>/latest,
                 never a staged retrain) -> DP-noise -> sign + upload.
  sync_global()  fetch the coordinator-signed global model -> verify sig+hash ->
                 save it as a STAGED detector version with a promote_after stamp.
  promote_due()  soak gate: staged federated versions whose promote_after has
                 elapsed are promoted to active + hot-reloaded (unless the admin
                 promoted/rejected them first). Admin early-promote / reject /
                 rollback reuse the normal /models/* endpoints.

Shared by the REST routes (api/routes/fl_local.py) and the background poller
(api/main.py), so manual and automatic participation run identical code.
"""

import json
import os
import time
from typing import Optional

from federated.coordinator_client import CoordinatorClient
from federated.privacy import apply_differential_privacy
from shared.logging import get_logger

logger = get_logger("federated.participation")


class FLParticipationError(Exception):
    """Raised for expected participation failures (not configured, no round, …)."""


def make_client(state, *, session=None, timeout: float = 30.0) -> CoordinatorClient:
    """Build a CoordinatorClient from this org's stored config + keypair. With a
    real (production) session it wires mTLS from the stored cert + decrypted key;
    with an injected session (tests) it relies on the bootstrap api-key header."""
    cfg = state.get_full_config()
    if not cfg or not cfg.get("coordinator_url"):
        raise FLParticipationError(
            "FL coordinator not configured — call /fl/local/configure first")
    return CoordinatorClient(
        base_url=cfg["coordinator_url"],
        org_id=cfg["org_id"],
        sign_fn=state.sign_attestation,
        verify_fn=state.verify_coordinator_signature,
        api_key=state.get_api_key(),
        client_cert_pem=cfg.get("client_cert_pem"),
        client_key_pem=(state.get_private_key_pem() if session is None else None),
        ca_cert_pem=cfg.get("ca_cert_pem"),
        session=session,
        timeout=timeout,
    )


def _active_detector_model(model_store, detector: str) -> tuple[bytes, int]:
    """Bytes + reported sample count of the detector's ACTIVE model (the model
    the detector is actually running — the `latest` symlink, which only ever
    points at a promoted/active version, never a staged retrain)."""
    latest = (model_store.base_dir / detector / "latest").resolve()
    model_path = latest / "model.json"
    if not model_path.exists():
        raise FLParticipationError(
            f"No active model for detector {detector!r} — train/promote one first")
    model_bytes = model_path.read_bytes()
    num_examples = 100
    mpath = latest / "manifest.json"
    if mpath.exists():
        meta = (json.loads(mpath.read_text()).get("metadata") or {})
        num_examples = int(meta.get("n_train", 0) or 0) + int(meta.get("n_eval", 0) or 0) \
            or num_examples
    return model_bytes, num_examples


def contribute(state, model_store, *, detector: str, round_id: Optional[int] = None,
               epsilon: float = 1.0, session=None) -> dict:
    """Contribute the active detector model to a round. round_id=None joins the
    most recent open round this org is invited to (discovery)."""
    client = make_client(state, session=session)
    try:
        if round_id is None:
            rounds = client.list_active_rounds()
            if not rounds:
                raise FLParticipationError("no open round to join right now")
            round_id = rounds[0]["round_id"]
        model_bytes, num_examples = _active_detector_model(model_store, detector)
        noised = apply_differential_privacy(model_bytes, epsilon=epsilon)
        cid = state.record_contribution_start(round_id, num_examples)
        try:
            resp = client.submit_contribution(round_id, noised, num_examples)
        except Exception as e:
            state.record_contribution_result(cid, "failed", reason=str(e)[:300])
            raise
        state.record_contribution_result(cid, "accepted",
                                         reason="received by coordinator")
        logger.info("FL contribution submitted", detector=detector,
                    round_id=round_id, num_examples=num_examples)
        return {"round_id": round_id, "detector": detector,
                "contribution_id": cid, "num_examples": num_examples, "coordinator": resp}
    finally:
        client.close()


def sync_global(state, model_store, *, detector: str, session=None,
                verify_hours: float = 24.0) -> dict:
    """Fetch + verify the active global model and stage it as a detector version
    (soaking until promote_after). Idempotent: skips if this global version is
    already staged/active locally."""
    client = make_client(state, session=session)
    try:
        gm = client.fetch_global_model()        # verifies coordinator sig + hash
    finally:
        client.close()

    fl_vid = gm.get("version_id")
    for v in model_store.list_versions(detector):
        meta = v.get("metadata") or {}
        if meta.get("source") == "federated" and meta.get("fl_version_id") == fl_vid \
                and v.get("status") in ("staged", "active"):
            return {"detector": detector, "skipped": "already have this global version",
                    "fl_version_id": fl_vid}

    import xgboost as xgb
    booster = xgb.Booster()
    booster.load_model(bytearray(gm["model_bytes"]))
    metadata = {
        "source": "federated",
        "fl_round_id": gm.get("round_id"),
        "fl_version_id": fl_vid,
        "promote_after": time.time() + verify_hours * 3600,
        "feature_names": list(booster.feature_names or []),
        "anonymize": os.environ.get("APT_ANONYMIZE", "1") == "1",
    }
    version = model_store.save_model(booster, detector, metadata=metadata, status="staged")
    logger.info("Federated global model staged for soak", detector=detector,
                version=version, promote_after=metadata["promote_after"])
    return {"detector": detector, "version": version,
            "fl_round_id": gm.get("round_id"), "fl_version_id": fl_vid,
            "promote_after": metadata["promote_after"], "verify_hours": verify_hours}


def promote_due(model_store, registry, detectors) -> list[dict]:
    """Soak gate: promote + hot-reload any staged FEDERATED version whose
    promote_after has elapsed (auto hot-reload without admin intervention)."""
    promoted = []
    now = time.time()
    for det in detectors:
        for v in model_store.list_staged(det):
            meta = v.get("metadata") or {}
            if meta.get("source") != "federated":
                continue
            pa = meta.get("promote_after")
            if pa is None or now < pa:
                continue
            try:
                model_store.promote(det, v["version"])
                registry.hot_reload(det, str(model_store.base_dir / det / "latest"))
                promoted.append({"detector": det, "version": v["version"]})
                logger.info("Federated model auto-promoted after soak",
                            detector=det, version=v["version"])
            except Exception as e:
                logger.error("Federated auto-promote failed",
                             detector=det, version=v["version"], error=str(e))
    return promoted


def run_auto_cycle(state, model_store, *, session=None, verify_hours: float = 24.0) -> dict:
    """One tick of automatic participation: when opted-in + mode=auto + a detector
    is configured, contribute to an open round and stage any published global
    model. Errors are swallowed into the result (never kills the poller)."""
    s = state.get_settings()
    if s.get("mode") != "auto":
        return {"skipped": "manual mode"}
    if not state.get_opt_in().get("opted_in"):
        return {"skipped": "not opted in"}
    detector = s.get("detector")
    if not detector:
        return {"skipped": "no detector configured for auto mode"}
    out: dict = {"detector": detector}
    try:
        out["contribute"] = contribute(state, model_store, detector=detector,
                                       epsilon=s.get("epsilon", 1.0), session=session)
    except Exception as e:
        out["contribute_skipped"] = str(e)[:200]
    try:
        out["sync"] = sync_global(state, model_store, detector=detector,
                                  session=session, verify_hours=verify_hours)
    except Exception as e:
        out["sync_skipped"] = str(e)[:200]
    return out


# ── Mutual-ack removal (org self-removal handshake) ─────────────────────────

def request_leave(state, *, reason: str = "", session=None) -> dict:
    """Org-side step 1: send a signed leave request to the coordinator and mark
    local removal state 'requested'. The org is then 'leave_pending' on the
    coordinator (no longer invited to rounds). Completion requires the operator
    to approve, after which the org calls finalize_leave()."""
    client = make_client(state, session=session)
    try:
        resp = client.request_leave(reason=reason)
    finally:
        client.close()
    state.set_removal_state("requested", "leave-request")
    logger.info("FL leave requested", coordinator_status=resp.get("status"))
    return resp


def finalize_leave(state, *, keep_contributions: bool = True, session=None) -> dict:
    """Org-side step 2: poll the coordinator; if the operator approved (status
    'revoked', coordinator signature verified) WIPE local membership credentials
    (keeping the contributions history by default). No-op (finalized=False)
    while still awaiting operator approval."""
    client = make_client(state, session=session)
    try:
        status = client.get_removal_status()
    finally:
        client.close()
    if not status.get("confirmed"):
        return {"finalized": False, "status": status.get("status"),
                "note": "still awaiting operator approval"}
    purge = state.purge_membership(keep_contributions=keep_contributions)
    logger.info("FL membership purged after coordinator approval", **purge)
    return {"finalized": True, "status": "revoked", "purge": purge}
