#!/usr/bin/env python3

import argparse
import socket
import ssl
from datetime import datetime, timezone

parser = argparse.ArgumentParser(
    description="Check a remote TLS certificate"
)

parser.add_argument(
    "host",
    help="IP address or hostname to connect to"
)

parser.add_argument(
    "--port",
    type=int,
    default=443,
    help="TLS port (default: 443)"
)

parser.add_argument(
    "--server-name",
    required=True,
    help="TLS server name used for SNI and hostname validation"
)

args = parser.parse_args()

HOST = args.host
PORT = args.port
SERVER_NAME = args.server_name


def flatten_name(name):
    parts = []

    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")

    return ", ".join(parts)

context = ssl.create_default_context()

try:
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        with context.wrap_socket(
            sock,
            server_hostname=SERVER_NAME
        ) as tls:
            cert = tls.getpeercert()

except socket.timeout:
    print(f"[FAIL] Connection to {HOST}:{PORT} timed out")
    raise SystemExit(1)

except ConnectionRefusedError:
    print(f"[FAIL] Connection to {HOST}:{PORT} was refused")
    raise SystemExit(1)

except socket.gaierror as error:
    print(f"[FAIL] DNS resolution failed: {error}")
    raise SystemExit(1)

except ssl.SSLCertVerificationError as error:
    print("[FAIL] TLS certificate verification failed")
    print(f"[INFO] {error}")
    raise SystemExit(2)

except ssl.SSLError as error:
    print("[FAIL] TLS negotiation failed")
    print(f"[INFO] {error}")
    raise SystemExit(2)

except OSError as error:
    print(f"[FAIL] Network error: {error}")
    raise SystemExit(1)


subject = flatten_name(cert["subject"])
issuer = flatten_name(cert["issuer"])

not_before = datetime.strptime(
    cert["notBefore"],
    "%b %d %H:%M:%S %Y %Z"
).replace(tzinfo=timezone.utc)

not_after = datetime.strptime(
    cert["notAfter"],
    "%b %d %H:%M:%S %Y %Z"
).replace(tzinfo=timezone.utc)

now = datetime.now(timezone.utc)

days_remaining = (not_after - now).days


print("=== TLS Certificate Check ===")
print(f"Host:           {HOST}")
print(f"Port:           {PORT}")
print(f"Server Name:    {SERVER_NAME}")
print()

print(f"Subject:        {subject}")
print(f"Issuer:         {issuer}")
print(f"Serial Number:  {cert['serialNumber']}")
print(f"Valid From:     {not_before}")
print(f"Valid Until:    {not_after}")
print(f"Days Remaining: {days_remaining}")
print()

if days_remaining < 0:
    print("[ALERT] Certificate has expired")
    raise SystemExit(3)

elif days_remaining <= 7:
    print(f"[ALERT] Certificate expires in {days_remaining} day(s)")
    raise SystemExit(3)

elif days_remaining <= 30:
    print(f"[WARN] Certificate expires in {days_remaining} day(s)")
    raise SystemExit(3)

else:
    print(f"[PASS] Certificate is valid for {days_remaining} more day(s)")
    raise SystemExit(0)
