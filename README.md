# Security Automation Toolkit

A practical security-operations toolkit for Linux server validation, TLS certificate inspection, and SSH troubleshooting.

This project was built as part of a hands-on security operations lab focused on Linux administration, SSH, PKI, authentication, troubleshooting, and automation.

## Tools

### security-health-check.sh

Performs a remote Linux server health and security assessment.

Checks include:

- Host reachability
- SSH port availability
- HTTPS port availability
- SSH service status
- NGINX service status
- Disk utilization
- Memory utilization
- CPU utilization
- Listening TCP ports
- Failed SSH authentication attempts
- Firewall visibility
- TLS certificate expiration

Example usage:

    ./security-health-check.sh 10.10.60.101

The script classifies results using:

- PASS
- WARN
- ALERT
- FAIL

The automated health check uses a standard SSH key for non-interactive execution, while hardware-backed FIDO2/YubiKey credentials are reserved for interactive administrative access.

---

### certcheck.py

Validates and inspects a remote TLS certificate.

Features include:

- TLS connection validation
- Certificate subject inspection
- Certificate issuer inspection
- Serial number reporting
- Validity date reporting
- Remaining certificate lifetime calculation
- Hostname verification
- Expiration warnings
- Network error handling
- TLS verification error handling
- Exit codes for automation

Example usage:

    ./certcheck.py 10.10.60.101 --server-name sec-server01

Custom port example:

    ./certcheck.py 10.10.60.101 --port 8443 --server-name sec-server01

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Certificate valid |
| 1 | Network or connection failure |
| 2 | TLS validation failure |
| 3 | Certificate expiration warning or alert |

The script can detect conditions such as:

- Valid and trusted certificates
- Hostname mismatch
- Certificate verification failure
- Closed or unreachable ports
- TLS negotiation problems
- Certificate expiration risk

---

### sshdiag.py

Troubleshoots SSH connectivity and host identity.

Checks include:

- DNS or address resolution
- TCP connectivity
- SSH protocol banner validation
- SSH host-key retrieval
- SHA256 host-key fingerprints
- known_hosts comparison

Example usage:

    ./sshdiag.py 10.10.60.101

The known_hosts validation can help identify:

- Server rebuilds
- Changed SSH host keys
- Stale known_hosts entries
- Unexpected server identity changes
- Potential man-in-the-middle conditions

The diagnostic flow follows a layered troubleshooting approach:

    Address Resolution
        |
        v
    TCP Reachability
        |
        v
    SSH Banner
        |
        v
    Host-Key Retrieval
        |
        v
    Fingerprint Validation
        |
        v
    known_hosts Comparison

---

## Lab Environment

The tools were developed and tested against Ubuntu Server systems in a virtualized security lab.

Example architecture:

    sec-admin01
        |
        | SSH / TLS diagnostics
        |
    sec-server01
        |
        +-- OpenSSH
        +-- NGINX
        +-- Internal PKI certificate

The administrative workstation performs remote diagnostics and security checks against the target Linux server.

---

## PKI Environment

The TLS environment uses a private certificate authority hierarchy.

Architecture:

    Root CA
        |
        v
    Intermediate CA
        |
        v
    sec-server01 Certificate

The server certificate contains:

- Server identity
- DNS Subject Alternative Name
- IP Subject Alternative Name
- Server Authentication Extended Key Usage
- Intermediate CA signature

The client system trusts the private Root CA and validates the full certificate chain presented by the server.

---

## SSH Security Model

The lab uses separate credentials for interactive administration and automation.

Interactive administrative access:

    YubiKey / FIDO2
        |
        +-- Hardware-backed SSH credential
        +-- FIDO2 PIN
        +-- Physical user presence
        +-- Non-exportable hardware-backed signing

Automation:

    Standard Ed25519 SSH Key
        |
        +-- Used for scripted health checks
        +-- Suitable for non-interactive execution
        +-- Restricted to automation use

This separation avoids weakening hardware-backed authentication simply to make automated scripts easier to execute.

---

## Skills Demonstrated

This project demonstrates practical experience with:

- Linux administration
- Bash scripting
- Python scripting
- SSH
- SSH host keys
- SSH fingerprints
- known_hosts validation
- PKI
- Certificate authorities
- Intermediate certificate authorities
- TLS certificates
- Certificate expiration monitoring
- Hostname validation
- OpenSSL
- Network troubleshooting
- Authentication troubleshooting
- Linux services
- systemd
- NGINX
- Process and service validation
- TCP port analysis
- Security monitoring logic
- Error handling
- Exit codes
- Automation design
- Privilege boundaries
- FIDO2
- YubiKey authentication
- Security operations troubleshooting

---

## Security Design Notes

### Privilege Boundaries

The health-check script does not automatically weaken sudo permissions simply to make all checks succeed.

If a command requires elevated privileges, the script reports that limitation explicitly.

Example:

    [WARN] Cannot determine UFW status without sudo privileges

This preserves the principle of least privilege.

### Authentication Separation

Hardware-backed FIDO2/YubiKey credentials are used for interactive administrator access.

Standard SSH credentials are used for automation.

This avoids requiring hardware interaction for unattended scripts while preserving stronger authentication for administrative sessions.

### TLS Validation

The certificate inspection tool performs normal certificate validation instead of disabling verification.

This allows the tool to identify:

- Untrusted certificate chains
- Incorrect hostnames
- Expired certificates
- TLS negotiation failures

### SSH Host-Key Validation

The SSH diagnostic tool compares currently presented SSH host keys against the local known_hosts database.

A mismatch may indicate:

- A legitimate server rebuild
- SSH host-key regeneration
- A stale known_hosts entry
- A server identity change
- A possible man-in-the-middle condition

Host-key mismatches should be independently verified before updating known_hosts.

---

## Example Health Check Output

    ============================================================
                  SECURITY HEALTH CHECK
    ============================================================
    Target:       10.10.60.101
    Remote user:  notadm1n
    ============================================================

    [1] Host Reachability
    [PASS] Host is reachable

    [2] SSH Port
    [PASS] TCP/22 is open

    [3] HTTPS Port
    [PASS] TCP/443 is open

    [4] Remote System Checks
    [PASS] Connected to: sec-server01
    [PASS] SSH service is active
    [PASS] NGINX service is active

    [5] Disk Usage
    [PASS] Root filesystem usage: 50%

    [6] Memory Usage
    [PASS] Memory usage: 19%

    [7] CPU Usage
    [PASS] CPU utilization: 0%

    [8] Listening TCP Ports
    0.0.0.0:443
    0.0.0.0:22

    [9] Recent Failed SSH Logins
    [PASS] No failed SSH authentication attempts in the last 24 hours

    [10] Firewall Status
    [WARN] Cannot determine UFW status without sudo privileges

    [11] TLS Certificate Expiration
    [PASS] TLS certificate expires in 364 day(s)

---

## Example Certificate Check

    ./certcheck.py 10.10.60.101 --server-name sec-server01

Example successful result:

    [PASS] Certificate is valid for 363 more day(s)

Example hostname mismatch:

    [FAIL] TLS certificate verification failed
    [INFO] Hostname mismatch

Example closed port:

    [FAIL] Connection to 10.10.60.101:444 was refused

---

## Example SSH Diagnostic

    ./sshdiag.py 10.10.60.101

Example result:

    [1] Address Resolution
    [PASS] Resolved address: 10.10.60.101

    [2] SSH Connectivity
    [PASS] TCP/22 is reachable
    [PASS] SSH banner received: SSH-2.0-OpenSSH

    [3] SSH Host Key
    [PASS] Retrieved SSH host keys

    [INFO] Key type: ssh-ed25519
    [INFO] Fingerprint: SHA256:...

    [4] known_hosts Verification
    [PASS] Presented host keys match known_hosts

---

## Repository Structure

    security-automation/
    |
    +-- security-health-check.sh
    +-- certcheck.py
    +-- sshdiag.py
    +-- README.md

---

## Requirements

Linux system with:

- Bash
- Python 3
- OpenSSH client utilities
- OpenSSL
- netcat
- Standard Linux networking utilities

Ubuntu example:

    sudo apt install python3 openssh-client openssl netcat-openbsd

---

## Usage

Clone the repository:

    git clone https://github.com/edilbertorodriguez/security-automation.git

Enter the project directory:

    cd security-automation

Make scripts executable:

    chmod +x security-health-check.sh
    chmod +x certcheck.py
    chmod +x sshdiag.py

Run the Linux server health check:

    ./security-health-check.sh 10.10.60.101

Run the TLS certificate checker:

    ./certcheck.py 10.10.60.101 --server-name sec-server01

Run the SSH diagnostic tool:

    ./sshdiag.py 10.10.60.101

---

## Project Goals

The primary goal of this project is to practice converting manual security and systems troubleshooting procedures into repeatable automation.

The project focuses on operational security tasks such as:

- Server health validation
- Authentication troubleshooting
- SSH identity verification
- TLS certificate validation
- Security configuration visibility
- Network service troubleshooting
- Error classification
- Automation-friendly exit codes

---

## Project Status

Completed tools:

- security-health-check.sh
- certcheck.py
- sshdiag.py

The toolkit was developed as part of a broader hands-on security operations readiness lab.
