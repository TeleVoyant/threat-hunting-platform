"""
Cross-repo FL integration: the org platform's participation client against the
REAL apt-fl-coordinator (in-process TestClient injected as the transport).

Proves the interfacing end-to-end:
  enroll -> configure -> contribute (DP + sign) -> coordinator aggregate+publish
  -> org fetch + verify global model -> stage as detector version -> soak-promote.

Run:  PYTHONPATH=. OMP_NUM_THREADS=1 python tests/test_fl_integration.py
(run from the threat-hunting-platform/ directory; the sibling apt-fl-coordinator/
 is added to sys.path automatically).
"""

import base64
import hashlib
import os
import sys
import tempfile
from pathlib import Path

import yaml
from cryptography.fernet import Fernet

_TMP = tempfile.mkdtemp(prefix="fl_integ_")
_COORD = str(Path(__file__).resolve().parents[2] / "apt-fl-coordinator")
sys.path.insert(0, _COORD)

# ── env (must be set before importing either app) ───────────────────────────
os.environ.update({
    # org side
    "FL_LOCAL_FERNET_KEY": Fernet.generate_key().decode(),
    "MODEL_SIGNING_KEY": "integration-signing-key",
    "APT_ANONYMIZE": "0",
    "FL_GLOBAL_MODEL_VERIFY_HOURS": "0",      # no soak wait in the test
    # coordinator side
    "FL_DATA_DIR": f"{_TMP}/coord",
    "FL_CA_DIR": f"{_TMP}/coord/ca",
    "FL_USERS_FILE": f"{_TMP}/coord/users.yml",
    "FL_JWT_SECRET": "integration-secret-at-least-32-bytes!!",
    "FL_DEV_ALLOW_HEADER_MTLS": "1",
    "FL_OBSERVATION_HOURS": "0",
    # FL_VALIDATION_DATA unset -> coordinator uses structure-only trust
    "OMP_NUM_THREADS": "1",
})

# ── bootstrap coordinator CA + operator roster, then build it ───────────────
from flproto.ca import init_ca                                   # noqa: E402  (apt-fl-coordinator)
Path(f"{_TMP}/coord").mkdir(parents=True, exist_ok=True)
init_ca(f"{_TMP}/coord/ca", coordinator_hostname="localhost")
OP_KEY = "integration-operator-key"
yaml.safe_dump({"users": [{"username": "root", "role": "fl_admin",
                           "api_key_hash": hashlib.sha256(OP_KEY.encode()).hexdigest()}]},
               open(f"{_TMP}/coord/users.yml", "w"))

from fastapi.testclient import TestClient                        # noqa: E402
from coordinator.app import app as coord_app                     # noqa: E402  (apt-fl-coordinator)
coord = TestClient(coord_app)
OP = {"X-FL-API-Key": OP_KEY}

# ── org-side modules ────────────────────────────────────────────────────────
import numpy as np                                               # noqa: E402
import xgboost as xgb                                            # noqa: E402
from federated.local_state import LocalFLState                  # noqa: E402  (threat-hunting-platform)
from federated.attestation import generate_keypair, private_key_to_pem, public_key_to_pem  # noqa: E402
from federated import participation                             # noqa: E402
from detection.model_store import ModelStore                    # noqa: E402

DET = "lateral_movement"
FEATS = [f"f{i}" for i in range(10)]


class StubRegistry:
    def __init__(self): self.calls = []
    def hot_reload(self, name, path): self.calls.append((name, path))


def _make_active_detector(store):
    rng = np.random.default_rng(0)
    X = rng.normal(size=(80, 10)); y = (X[:, 0] > 0).astype(int)
    dm = xgb.DMatrix(X, label=y, feature_names=FEATS, nthread=1)
    b = xgb.train({"objective": "binary:logistic", "max_depth": 3}, dm, num_boost_round=5)
    store.save_model(b, DET, metadata={"feature_names": FEATS, "anonymize": False,
                                       "n_train": 80}, status="active")


def test_fl_integration():
    state = LocalFLState(db_path=f"{_TMP}/org/state.db")
    store = ModelStore(base_dir=f"{_TMP}/org/models", signing_key=os.environ["MODEL_SIGNING_KEY"])
    _make_active_detector(store)

    # 1) org generates its keypair locally (keypair/init)
    priv, pub = generate_keypair()
    fernet = Fernet(os.environ["FL_LOCAL_FERNET_KEY"].encode())
    state.store_keypair(
        private_key_enc=base64.b64encode(fernet.encrypt(private_key_to_pem(priv))).decode(),
        public_key_pem=public_key_to_pem(pub).decode(), generated_by="admin")

    # 2) operator enrolls the org at the coordinator with the org's public key
    enr = coord.post("/fl/orgs/enroll", json={
        "org_id": "udom", "display_name": "UDOM",
        "public_key_pem": state.get_public_key_pem()}, headers=OP)
    assert enr.status_code == 201, enr.text
    pkg = enr.json()

    # 3) org configures from the enrollment package + opts in + picks the detector
    state.configure_coordinator(
        coordinator_url="http://testserver", org_id="udom",
        api_key_enc=base64.b64encode(fernet.encrypt(pkg["api_key"].encode())).decode(),
        configured_by="admin",
        client_cert_pem=pkg["client_cert_pem"], ca_cert_pem=pkg["ca_cert_pem"],
        coordinator_pub_pem=pkg["coordinator_pub_pem"])
    state.set_opt_in(True, "admin")
    state.set_settings(mode="manual", detector=DET, epsilon=1.0, by_user="admin")

    # 4) operator opens a round; org discovers + verifies the signed announcement
    rid = coord.post("/fl/rounds/start", json={"min_clients": 1}, headers=OP).json()["round_id"]
    client = participation.make_client(state, session=coord)
    rounds = client.list_active_rounds()
    assert rid in [r["round_id"] for r in rounds], rounds
    ann = client.verify_announcement(rid)           # raises if coordinator sig invalid
    assert ann["round_id"] == rid
    client.close()

    # 5) org contributes its ACTIVE detector model (DP-noised, signed) via the client
    res = participation.contribute(state, store, detector=DET, round_id=rid,
                                   epsilon=1.0, session=coord)
    assert res["coordinator"]["accepted"] is True, res
    assert state.list_contributions()[0]["status"] == "accepted"

    # 6) operator aggregates + publishes
    agg = coord.post(f"/fl/rounds/{rid}/aggregate", headers=OP)
    assert agg.status_code == 200 and "udom" in agg.json()["accepted_orgs"], agg.text
    assert coord.post(f"/fl/rounds/{rid}/publish", headers=OP).json()["status"] == "active"

    # 7) org fetches + verifies + stages the global model as a detector version
    sync = participation.sync_global(state, store, detector=DET, session=coord, verify_hours=0.0)
    staged = store.list_staged(DET)
    assert any(v["version"] == sync["version"] and
               (v["metadata"] or {}).get("source") == "federated" for v in staged), staged

    # 8) soak elapsed (verify_hours=0) -> auto-promote + hot-reload the global model
    reg = StubRegistry()
    promoted = participation.promote_due(store, reg, [DET])
    assert any(p["detector"] == DET for p in promoted), promoted
    assert reg.calls and reg.calls[0][0] == DET           # detector hot-reloaded

    # the federated model is now the live detector; the original is kept as a
    # distinct archived version (so the admin can roll back).
    versions = store.list_versions(DET)
    assert len(versions) == 2, f"expected original + federated, got {versions}"
    active = [v for v in versions if v["status"] == "active"]
    archived = [v for v in versions if v["status"] == "archived"]
    assert len(active) == 1 and (active[0]["metadata"] or {}).get("source") == "federated", active
    assert len(archived) == 1 and (archived[0]["metadata"] or {}).get("source") != "federated", archived

    # rollback reuses the platform's ModelStore: the original detector goes live again.
    store.rollback(DET, archived[0]["version"])
    assert (store.base_dir / DET / "latest").resolve().name == archived[0]["version"]
    return res["round_id"], sync["version"]


def test_fl_removal():
    """Org self-removal mutual-ack handshake: request_leave (signed) -> operator
    approve -> finalize_leave verifies the coordinator's signature and WIPES the
    org's credentials while KEEPING its contributions history. Plus force-purge."""
    state = LocalFLState(db_path=f"{_TMP}/org2/state.db")
    fernet = Fernet(os.environ["FL_LOCAL_FERNET_KEY"].encode())
    priv, pub = generate_keypair()
    state.store_keypair(
        private_key_enc=base64.b64encode(fernet.encrypt(private_key_to_pem(priv))).decode(),
        public_key_pem=public_key_to_pem(pub).decode(), generated_by="admin")
    enr = coord.post("/fl/orgs/enroll", json={
        "org_id": "udom2", "display_name": "UDOM2",
        "public_key_pem": state.get_public_key_pem()}, headers=OP)
    assert enr.status_code == 201, enr.text
    pkg = enr.json()
    state.configure_coordinator(
        coordinator_url="http://testserver", org_id="udom2",
        api_key_enc=base64.b64encode(fernet.encrypt(pkg["api_key"].encode())).decode(),
        configured_by="admin",
        client_cert_pem=pkg["client_cert_pem"], ca_cert_pem=pkg["ca_cert_pem"],
        coordinator_pub_pem=pkg["coordinator_pub_pem"])
    state.set_opt_in(True, "admin")
    # a past contribution we expect to KEEP through removal
    cid = state.record_contribution_start(round_id=99, num_examples=123)
    state.record_contribution_result(cid, "accepted")

    # 1) org requests to leave (signed) -> coordinator 'leave_pending'
    resp = participation.request_leave(state, reason="study complete", session=coord)
    assert resp["status"] == "leave_pending", resp
    assert state.get_removal_state()["state"] == "requested"

    # 2) finalize BEFORE approval is a no-op (still configured)
    pre = participation.finalize_leave(state, session=coord)
    assert pre["finalized"] is False and state.get_config() is not None, pre

    # 3) operator approves the removal
    ap = coord.post("/fl/orgs/udom2/approve-removal", headers=OP)
    assert ap.status_code == 200 and ap.json()["status"] == "revoked", ap.text

    # 4) finalize AFTER approval -> verify coordinator signature + wipe credentials
    fin = participation.finalize_leave(state, session=coord)
    assert fin["finalized"] is True, fin
    assert state.get_config() is None, "coordinator config must be wiped"
    assert state.has_keypair() is False, "keypair must be wiped"
    assert state.get_api_key() is None, "api key must be wiped"
    assert state.get_removal_state()["state"] == "completed"
    kept = state.list_contributions()
    assert len(kept) == 1 and kept[0]["round_id"] == 99, ("contributions must be kept", kept)

    # 5) force-purge: local-only wipe (no coordinator coordination)
    s2 = LocalFLState(db_path=f"{_TMP}/org3/state.db")
    p2, pub2 = generate_keypair()
    s2.store_keypair(
        private_key_enc=base64.b64encode(fernet.encrypt(private_key_to_pem(p2))).decode(),
        public_key_pem=public_key_to_pem(pub2).decode(), generated_by="admin")
    s2.configure_coordinator(coordinator_url="http://x", org_id="z",
                             api_key_enc="x", configured_by="admin")
    purge = s2.purge_membership(keep_contributions=True)
    assert s2.get_config() is None and s2.has_keypair() is False, "force purge must wipe"
    assert "keypair" in purge["purged"]

    print("PASS test_fl_removal")


def test_fl_self_enroll():
    """Org-side SECURE self-enrollment against the REAL coordinator: org generates
    Ed25519 + X25519 keys, the operator mints a token, the org PoP-signs + redeems
    it, UNSEALS the package with its X25519 key, verifies the CA fingerprint, and
    configures. Proves the cross-repo sealed-box + PoP crypto interop."""
    import json as _json, hashlib as _hl
    from federated.attestation import build_enroll_pop
    from federated.seal_box import (
        generate_x25519_keypair, x25519_private_to_pem, x25519_public_to_pem, unseal)
    state = LocalFLState(db_path=f"{_TMP}/orgse/state.db")
    fernet = Fernet(os.environ["FL_LOCAL_FERNET_KEY"].encode())
    ep, epub = generate_keypair()
    xp, xpub = generate_x25519_keypair()
    state.store_keypair(
        private_key_enc=base64.b64encode(fernet.encrypt(private_key_to_pem(ep))).decode(),
        public_key_pem=public_key_to_pem(epub).decode(), generated_by="admin",
        x25519_private_enc=base64.b64encode(fernet.encrypt(x25519_private_to_pem(xp))).decode(),
        x25519_public_pem=x25519_public_to_pem(xpub).decode())

    mint = coord.post("/fl/orgs/enroll-token",
                      json={"org_id": "udom3", "display_name": "UDOM3", "ttl_minutes": 60},
                      headers=OP)
    assert mint.status_code == 201, mint.text
    token, ca_sha256 = mint.json()["token"], mint.json()["ca_sha256"]

    org_id = _json.loads(base64.urlsafe_b64decode(token.encode()).rsplit(b".", 1)[0])["org_id"]
    pop = build_enroll_pop(token_b64=token, x25519_pub_pem=state.get_x25519_public_pem())
    r = coord.post("/fl/orgs/enroll-with-token", json={
        "token": token, "org_id": org_id,
        "ed25519_pub_pem": state.get_public_key_pem(),
        "x25519_pub_pem": state.get_x25519_public_pem(),
        "pop_signature": state.sign_attestation(pop).hex()})
    assert r.status_code == 201, r.text

    pkg = _json.loads(unseal(state.get_x25519_private_pem(), r.json()["sealed_package_b64"]))
    assert _hl.sha256(pkg["ca_cert_pem"].encode()).hexdigest() == ca_sha256, "CA fingerprint mismatch"
    state.configure_coordinator(
        coordinator_url="http://testserver", org_id=org_id,
        api_key_enc=base64.b64encode(fernet.encrypt(pkg["api_key"].encode())).decode(),
        configured_by="admin", client_cert_pem=pkg["client_cert_pem"],
        ca_cert_pem=pkg["ca_cert_pem"], coordinator_pub_pem=pkg["coordinator_pub_pem"])
    assert state.get_config()["org_id"] == "udom3"

    # the self-enrolled org can participate: operator opens a round, org discovers it
    rid = coord.post("/fl/rounds/start", json={"min_clients": 1}, headers=OP).json()["round_id"]
    cl = participation.make_client(state, session=coord)
    try:
        assert rid in [x["round_id"] for x in cl.list_active_rounds()], "self-enrolled org not invited"
    finally:
        cl.close()
    print("PASS test_fl_self_enroll")


if __name__ == "__main__":
    rid, ver = test_fl_integration()
    test_fl_removal()
    test_fl_self_enroll()
    print("PASS test_fl_integration")
    print(f"  org contributed to coordinator round {rid}; global model staged "
          f"as {ver} and auto-promoted as the live detector")
    print("\nInterfacing verified: enroll -> configure -> contribute -> aggregate "
          "-> publish -> fetch+verify -> stage -> soak-promote")
