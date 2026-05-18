#!/usr/bin/env python3
# federated/mtls_demo.py
"""
End-to-end mTLS demo over real TCP.

Spins up a real uvicorn process with TLS + client-cert-required, then
makes real HTTPS requests using each org's client cert. Demonstrates
that mutual TLS + application-layer signatures fail closed under five
adversarial scenarios:

  1. Org with valid client cert + correct signature   →  202 accepted
  2. NO client cert presented                          →  TLS handshake aborts
  3. Client cert from a DIFFERENT CA                   →  TLS handshake aborts
  4. Valid mTLS + signature forged with wrong key      →  403 (sig verify fail)
  5. Valid mTLS + cross-org attestation                →  403 (org_id mismatch)

Architectural note: uvicorn doesn't surface the verified peer cert into
the ASGI scope. So in this demo:
  - mTLS at transport guarantees: only CA-signed clients can establish
    a TCP connection at all (uvicorn refuses TLS handshake otherwise)
  - Application-layer Ed25519 signatures on each contribution provide
    PER-MESSAGE identity + non-repudiation (attestation.org_id is
    verified against the stored public key)
  - Bootstrap API key is the session credential for non-contribute
    endpoints (challenge issuance, etc.)

Each check produces a one-line PASS/FAIL on the console, suitable for
inclusion in Chapter 7 as a security-test transcript.
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import requests
import urllib3
urllib3.disable_warnings()

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from federated.attestation import (
    build_contribution_attestation, generate_keypair,
    private_key_to_pem, public_key_to_pem, sign as att_sign,
)
from federated.ca import (
    build_crl, init_ca, load_ca, issue_client_cert, cert_to_pem,
)
from federated.coordinator_store import CoordinatorStore
from federated.fl_security import (
    FLAuthManager, FLRole, FLUser, generate_fl_api_key,
)


PORT = 18889   # avoid collisions with the live coordinator on 8889


def _setup_demo_dir() -> dict:
    """Build a fresh CA + coordinator + enrolled UDoM org in a temp dir."""
    td = Path(tempfile.mkdtemp(prefix="mtls_demo_"))
    print(f"  demo workspace: {td}")

    # CA + coordinator server cert
    init_ca(ca_dir=str(td / "ca"), coordinator_hostname="localhost")
    ca_priv, ca_cert = load_ca(str(td / "ca"))

    # FL admin user (so we can pre-enroll UDoM via direct DB access)
    admin_key, admin_kh = generate_fl_api_key()
    fl_users_yml = td / "fl_users.yml"
    fl_users_yml.write_text(
        f"users:\n"
        f"  - username: admin\n    role: fl_admin\n    api_key_hash: {admin_kh}\n"
    )

    # ── Pre-create UDoM keypair + enroll in the coordinator DB ──────────
    udom_priv, udom_pub = generate_keypair()
    udom_priv_pem = private_key_to_pem(udom_priv)
    udom_pub_pem  = public_key_to_pem(udom_pub)

    udom_cert = issue_client_cert(
        ca_priv=ca_priv, ca_cert=ca_cert,
        client_pub=udom_pub, org_id="udom", display_name="UDoM",
    )
    udom_cert_pem = cert_to_pem(udom_cert)

    # Pre-populate coordinator DB so we can hit /fl/rounds/* via mTLS.
    # Path MUST match what coordinator_app.build_app() expects:
    # f"{FL_DATA_DIR}/coordinator.db".
    cs = CoordinatorStore(db_path=str(td / "coordinator.db"))
    udom_api_key, udom_api_kh = generate_fl_api_key()
    cs.enroll_org(
        org_id="udom", display_name="UDoM",
        api_key_hash=udom_api_kh, enrolled_by="demo",
        public_key_pem=udom_pub_pem.decode(),
        cert_pem=udom_cert_pem.decode(),
        cert_serial=str(udom_cert.serial_number),
    )

    # Also enroll a "revoked" org — still in DB, but marked revoked + serial in CRL
    revoked_priv, revoked_pub = generate_keypair()
    revoked_cert = issue_client_cert(
        ca_priv=ca_priv, ca_cert=ca_cert,
        client_pub=revoked_pub, org_id="revoked-org", display_name="Old Org",
    )
    cs.enroll_org(
        org_id="revoked-org", display_name="Old Org",
        api_key_hash=generate_fl_api_key()[1], enrolled_by="demo",
        public_key_pem=public_key_to_pem(revoked_pub).decode(),
        cert_pem=cert_to_pem(revoked_cert).decode(),
        cert_serial=str(revoked_cert.serial_number),
    )
    cs.set_org_status("revoked-org", "revoked")

    # Regenerate CRL with the revoked serial
    new_crl = build_crl(
        ca_priv, ca_cert,
        revoked_serials=[revoked_cert.serial_number],
    )
    (td / "ca" / "crl.pem").write_bytes(
        new_crl.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM)
    )

    # Write client cert + key files for httpx to load
    (td / "udom_cert.pem").write_bytes(udom_cert_pem)
    (td / "udom_key.pem").write_bytes(udom_priv_pem)
    (td / "udom_key.pem").chmod(0o600)
    (td / "revoked_cert.pem").write_bytes(cert_to_pem(revoked_cert))
    (td / "revoked_key.pem").write_bytes(private_key_to_pem(revoked_priv))

    # Issue a "rogue" cert from a DIFFERENT CA (not the federation CA)
    rogue_ca_dir = td / "rogue_ca"
    init_ca(ca_dir=str(rogue_ca_dir), coordinator_hostname="rogue.example.com")
    rogue_ca_priv, rogue_ca_cert = load_ca(str(rogue_ca_dir))
    rogue_priv, rogue_pub = generate_keypair()
    rogue_cert = issue_client_cert(
        ca_priv=rogue_ca_priv, ca_cert=rogue_ca_cert,
        client_pub=rogue_pub, org_id="udom", display_name="Impostor",
    )
    (td / "rogue_cert.pem").write_bytes(cert_to_pem(rogue_cert))
    (td / "rogue_key.pem").write_bytes(private_key_to_pem(rogue_priv))

    return {
        "td":                 td,
        "ca_dir":             str(td / "ca"),
        "fl_users_yml":       str(fl_users_yml),
        "admin_key":          admin_key,
        "udom_api_key":       udom_api_key,
        "udom_priv":          udom_priv,
        "udom_pub_pem":       udom_pub_pem,
        "udom_cert_path":     str(td / "udom_cert.pem"),
        "udom_key_path":      str(td / "udom_key.pem"),
        "revoked_cert_path":  str(td / "revoked_cert.pem"),
        "revoked_key_path":   str(td / "revoked_key.pem"),
        "rogue_cert_path":    str(td / "rogue_cert.pem"),
        "rogue_key_path":     str(td / "rogue_key.pem"),
        "ca_cert_path":       str(td / "ca" / "ca_cert.pem"),
        "coord_cert_path":    str(td / "ca" / "coordinator_cert.pem"),
        "coord_key_path":     str(td / "ca" / "coordinator_key.pem"),
    }


def _start_coordinator(env: dict) -> subprocess.Popen:
    """Spawn uvicorn with mTLS required."""
    args = [
        sys.executable, "-m", "uvicorn",
        "federated.coordinator_app:app",
        "--host",          "127.0.0.1",
        "--port",          str(PORT),
        "--ssl-certfile",  env["coord_cert_path"],
        "--ssl-keyfile",   env["coord_key_path"],
        "--ssl-ca-certs",  env["ca_cert_path"],
        "--ssl-cert-reqs", "2",                  # CERT_REQUIRED
        "--log-level",     "warning",
    ]
    proc_env = os.environ.copy()
    proc_env["FL_DATA_DIR"]  = str(env["td"])
    proc_env["FL_CA_DIR"]    = env["ca_dir"]
    proc_env["FL_USERS_FILE"] = env["fl_users_yml"]
    proc_env["FL_JWT_SECRET"] = "x" * 48

    print(f"\n  starting uvicorn (TLS + mTLS REQUIRED) on port {PORT}…")
    # Pipe stderr to a file so we can see startup errors without blocking
    stderr_log = open(env["td"] / "uvicorn.stderr.log", "wb")
    proc = subprocess.Popen(args, env=proc_env, stdout=subprocess.DEVNULL,
                              stderr=stderr_log,
                              cwd=str(Path(__file__).resolve().parent.parent))

    # Poll until alive
    base = f"https://localhost:{PORT}"
    started = time.time()
    last_err = None
    while time.time() - started < 15:
        if proc.poll() is not None:
            stderr_log.close()
            err = (env["td"] / "uvicorn.stderr.log").read_text()
            raise RuntimeError(f"uvicorn exited early (code {proc.returncode}):\n{err[-1000:]}")
        try:
            r = requests.get(f"{base}/",
                             verify=env["ca_cert_path"],
                             cert=(env["udom_cert_path"], env["udom_key_path"]),
                             timeout=2.0)
            if r.status_code in (200, 401, 403):
                print(f"  uvicorn ready in {time.time()-started:.1f}s")
                return proc
        except Exception as e:
            last_err = e
        time.sleep(0.5)

    proc.terminate()
    stderr_log.close()
    err = (env["td"] / "uvicorn.stderr.log").read_text()
    raise RuntimeError(f"uvicorn never became ready (last={last_err}):\n{err[-1000:]}")


def _start_round(env: dict) -> int:
    """Use the admin API key (over mTLS — admin is also a registered cert holder via UDoM cert here, but
    actually admin auth uses X-FL-API-Key, not mTLS. We send it through TLS though)."""
    base = f"https://localhost:{PORT}"
    r = requests.post(f"{base}/fl/rounds/start",
                      verify=env["ca_cert_path"],
                      cert=(env["udom_cert_path"], env["udom_key_path"]),
                      headers={"X-FL-API-Key": env["admin_key"]},
                      json={"epsilon": 1.0, "num_boost_rounds": 10, "min_clients": 1},
                      timeout=10.0)
    r.raise_for_status()
    return r.json()["round_id"]


def run_demo():
    env = _setup_demo_dir()
    coord_proc = None
    try:
        coord_proc = _start_coordinator(env)
        round_id = _start_round(env)
        print(f"\n  round {round_id} started")
        base = f"https://localhost:{PORT}"

        results = []

        # ─── Check 1: valid mTLS + valid signature → 202 ───────────────
        print("\n[1] Valid client cert + correct signature")
        cert = (env["udom_cert_path"], env["udom_key_path"])
        verify = env["ca_cert_path"]
        # API key auth at the application layer; mTLS at the transport layer.
        # The signed attestation is what proves identity per-message.
        org_hdr = {"X-FL-API-Key": env["udom_api_key"]}
        ch = requests.get(f"{base}/fl/rounds/{round_id}/challenge",
                          verify=verify, cert=cert,
                          headers=org_hdr, timeout=10.0).json()["challenge"]
        model = b"<<< model >>>"
        att = build_contribution_attestation(
            round_id=round_id, org_id="udom", model_bytes=model,
            num_examples=12345, challenge=ch,
        )
        sig = att_sign(env["udom_priv"], att).hex()
        r = requests.post(f"{base}/fl/rounds/{round_id}/contribute",
                          verify=verify, cert=cert, headers=org_hdr,
                          data={"attestation": att.decode(), "signature": sig},
                          files={"model": ("m.json", model, "application/octet-stream")},
                          timeout=10.0)
        ok = r.status_code == 202
        print(f"    status={r.status_code}  {'PASS' if ok else 'FAIL'}")
        results.append(("valid mTLS + sig → 202", ok))

        # ─── Check 2: NO client cert → TLS handshake aborts ────────────
        print("\n[2] No client cert presented")
        try:
            r = requests.get(f"{base}/fl/rounds/{round_id}/challenge",
                             verify=env["ca_cert_path"], timeout=5.0)
            handshake_failed = False
            print(f"    UNEXPECTED status={r.status_code} — TLS should have refused")
        except Exception as e:
            handshake_failed = True
            print(f"    TLS handshake aborted: {type(e).__name__}: {str(e)[:80]}  PASS")
        results.append(("no cert → handshake fail", handshake_failed))

        # ─── Check 3: cert from a DIFFERENT CA → TLS handshake aborts ──
        print("\n[3] Client cert from a different (rogue) CA")
        try:
            r = requests.get(f"{base}/fl/rounds/{round_id}/challenge",
                             verify=env["ca_cert_path"],
                             cert=(env["rogue_cert_path"], env["rogue_key_path"]),
                             timeout=5.0)
            wrong_ca_rejected = False
            print(f"    UNEXPECTED status={r.status_code} — TLS should have refused")
        except Exception as e:
            wrong_ca_rejected = True
            print(f"    TLS handshake aborted: {type(e).__name__}: {str(e)[:80]}  PASS")
        results.append(("rogue CA cert → handshake fail", wrong_ca_rejected))

        # ─── Check 4: valid mTLS but FORGED signature → 403 ────────────
        print("\n[4] Valid client cert + signature forged with WRONG key")
        cert = (env["udom_cert_path"], env["udom_key_path"])
        verify = env["ca_cert_path"]
        # API key auth at the application layer; mTLS at the transport layer.
        # The signed attestation is what proves identity per-message.
        org_hdr = {"X-FL-API-Key": env["udom_api_key"]}
        ch = requests.get(f"{base}/fl/rounds/{round_id}/challenge",
                          verify=verify, cert=cert,
                          headers=org_hdr, timeout=10.0).json()["challenge"]
        model = b"<<< model >>>"
        att = build_contribution_attestation(
            round_id=round_id, org_id="udom", model_bytes=model,
            num_examples=12345, challenge=ch,
        )
        fake_priv, _ = generate_keypair()
        forged_sig = att_sign(fake_priv, att).hex()
        r = requests.post(f"{base}/fl/rounds/{round_id}/contribute",
                          verify=verify, cert=cert, headers=org_hdr,
                          data={"attestation": att.decode(), "signature": forged_sig},
                          files={"model": ("m.json", model, "application/octet-stream")},
                          timeout=10.0)
        ok = r.status_code == 403 and "signature" in r.text.lower()
        print(f"    status={r.status_code} detail={r.json().get('detail','')[:60]}  {'PASS' if ok else 'FAIL'}")
        results.append(("mTLS OK + forged sig → 403", ok))

        # ─── Check 5: cross-org attestation — UDoM tries to upload as 'hospital' ────
        # mTLS handshake succeeds (UDoM has a valid cert), but the attestation
        # claims a different org_id than what the API key resolves to.
        print("\n[5] Cross-org attestation (UDoM signs but claims org_id='hospital')")
        cert = (env["udom_cert_path"], env["udom_key_path"])
        verify = env["ca_cert_path"]
        ch = requests.get(f"{base}/fl/rounds/{round_id}/challenge",
                          verify=verify, cert=cert, headers=org_hdr,
                          timeout=10.0).json()["challenge"]
        att = build_contribution_attestation(
            round_id=round_id, org_id="hospital",  # ← claims wrong org
            model_bytes=model, num_examples=12345, challenge=ch,
        )
        sig = att_sign(env["udom_priv"], att).hex()
        r = requests.post(f"{base}/fl/rounds/{round_id}/contribute",
                          verify=verify, cert=cert, headers=org_hdr,
                          data={"attestation": att.decode(), "signature": sig},
                          files={"model": ("m.json", model, "application/octet-stream")},
                          timeout=10.0)
        ok = r.status_code == 403 and "org_id" in r.text.lower()
        print(f"    status={r.status_code} detail={r.json().get('detail','')[:80]}  {'PASS' if ok else 'FAIL'}")
        results.append(("cross-org attestation → 403", ok))

        # ─── Summary ────────────────────────────────────────────────────
        print(f"\n{'═'*65}")
        n_pass = sum(1 for _, ok in results if ok)
        for name, ok in results:
            print(f"  {'✓' if ok else '✗'}  {name}")
        print(f"\n  {n_pass}/{len(results)} mTLS security checks passed")
        print(f"{'═'*65}")
        return 0 if n_pass == len(results) else 1

    finally:
        if coord_proc:
            coord_proc.terminate()
            try:
                coord_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                coord_proc.kill()
        # Leave td around for inspection unless --cleanup
        print(f"\n  artefacts kept at {env['td']} for inspection")


if __name__ == "__main__":
    sys.exit(run_demo())
