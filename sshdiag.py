#!/usr/bin/env python3

import argparse
import socket
import subprocess
from pathlib import Path

# ============================================================
# Argument Parsing
# ============================================================

parser = argparse.ArgumentParser(
    description="SSH connectivity and host-key diagnostic tool"
)

parser.add_argument(
    "host",
    help="Hostname or IP address to test"
)

parser.add_argument(
    "--port",
    type=int,
    default=22,
    help="SSH port (default: 22)"
)

args = parser.parse_args()

HOST = args.host
PORT = args.port


# ============================================================
# Header
# ============================================================

print("=== SSH Diagnostic ===")
print(f"Target: {HOST}:{PORT}")
print()


# ============================================================
# 1. DNS / Address Resolution
# ============================================================

print("[1] Address Resolution")

try:
    resolved_ip = socket.gethostbyname(HOST)
    print(f"[PASS] Resolved address: {resolved_ip}")

except socket.gaierror as error:
    print(f"[FAIL] DNS resolution failed: {error}")
    raise SystemExit(1)

print()


# ============================================================
# 2. TCP Connectivity + SSH Banner
# ============================================================

print("[2] SSH Connectivity")

try:
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        print(f"[PASS] TCP/{PORT} is reachable")

        sock.settimeout(5)

        banner = sock.recv(255).decode(
            errors="replace"
        ).strip()

        if banner.startswith("SSH-"):
            print(
                f"[PASS] SSH banner received: {banner}"
            )
        else:
            print(
                f"[WARN] Port {PORT} is open, "
                "but banner does not look like SSH"
            )
            print(f"[INFO] Banner: {banner!r}")

except socket.timeout:
    print(
        f"[FAIL] Connection to "
        f"{HOST}:{PORT} timed out"
    )
    raise SystemExit(2)

except ConnectionRefusedError:
    print(
        f"[FAIL] Connection to "
        f"{HOST}:{PORT} was refused"
    )
    raise SystemExit(2)

except OSError as error:
    print(f"[FAIL] Network error: {error}")
    raise SystemExit(2)

print()


# ============================================================
# 3. SSH Host-Key Retrieval
# ============================================================

print("[3] SSH Host Key")

try:
    result = subprocess.run(
        [
            "ssh-keyscan",
            "-p",
            str(PORT),
            "-T",
            "5",
            HOST,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )

    host_keys = [
        line
        for line in result.stdout.splitlines()
        if line and not line.startswith("#")
    ]

    if not host_keys:
        print("[FAIL] No SSH host keys were retrieved")
        raise SystemExit(3)

    print(
        f"[PASS] Retrieved "
        f"{len(host_keys)} SSH host key(s)"
    )

    for line in host_keys:

        parts = line.split()

        if len(parts) < 3:
            print(
                "[WARN] Retrieved malformed "
                "host-key entry"
            )
            continue

        key_type = parts[1]

        print()
        print(f"[INFO] Key type: {key_type}")

        fingerprint = subprocess.run(
            [
                "ssh-keygen",
                "-lf",
                "-",
            ],
            input=line + "\n",
            capture_output=True,
            text=True,
        )

        if fingerprint.returncode == 0:
            print(
                f"[INFO] Fingerprint: "
                f"{fingerprint.stdout.strip()}"
            )
        else:
            print(
                "[WARN] Unable to calculate "
                "fingerprint"
            )

except subprocess.TimeoutExpired:
    print("[FAIL] ssh-keyscan timed out")
    raise SystemExit(3)

except FileNotFoundError:
    print(
        "[FAIL] Required OpenSSH utility "
        "is not installed"
    )
    raise SystemExit(3)

# ============================================================
# 4. known_hosts Comparison
# ============================================================

print()
print("[4] known_hosts Verification")

known_hosts = Path.home() / ".ssh" / "known_hosts"

if not known_hosts.exists():
    print("[WARN] known_hosts file does not exist")

else:
    try:
        lookup = subprocess.run(
            [
                "ssh-keygen",
                "-F",
                HOST,
                "-f",
                str(known_hosts),
            ],
            capture_output=True,
            text=True,
        )

        if lookup.returncode != 0 or not lookup.stdout.strip():
            print("[WARN] Target is not currently present in known_hosts")

        else:
            known_lines = [
                line
                for line in lookup.stdout.splitlines()
                if line and not line.startswith("#")
            ]

            known_key_material = set()

            for line in known_lines:
                parts = line.split()

                if len(parts) >= 3:
                    known_key_material.add(
                        (parts[1], parts[2])
                    )

            current_key_material = set()

            for line in host_keys:
                parts = line.split()

                if len(parts) >= 3:
                    current_key_material.add(
                        (parts[1], parts[2])
                    )

            matches = known_key_material & current_key_material

            if matches:
                print(
                    f"[PASS] {len(matches)} presented host key(s) "
                    "match known_hosts"
                )

            else:
                print(
                    "[ALERT] Presented SSH host keys do not match known_hosts"
                )
                print(
                    "[INFO] Possible host-key change, server rebuild, "
                    "or man-in-the-middle condition"
                )
                raise SystemExit(4)

    except FileNotFoundError:
        print("[FAIL] ssh-keygen is not installed")
        raise SystemExit(4)

# ============================================================
# Complete
# ============================================================

print()
print("=== Diagnostic Complete ===")
raise SystemExit(0)
