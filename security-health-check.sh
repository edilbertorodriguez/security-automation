#!/usr/bin/env bash

# ============================================================
# Security Health Check
# Linux server health and security validation template
#
# Usage:
#   ./security-health-check.sh [target]
#
# Example:
#   ./security-health-check.sh 10.10.60.101
# ============================================================

# Do not use "set -e" because failed health checks are expected
# conditions that we want to report rather than terminate on.
set -uo pipefail

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

TARGET="${1:-10.10.60.101}"
REMOTE_USER="${REMOTE_USER:-notadm1n}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_PORT="${SSH_PORT:-22}"
HTTPS_PORT="${HTTPS_PORT:-443}"
TLS_SERVER_NAME="${TLS_SERVER_NAME:-sec-server01}"

WARN_DISK=80
ALERT_DISK=90

WARN_MEMORY=80
ALERT_MEMORY=90

WARN_CPU=80
ALERT_CPU=90

WARN_CERT_DAYS=30
ALERT_CERT_DAYS=7

echo "============================================================"
echo "              SECURITY HEALTH CHECK"
echo "============================================================"
echo "Target:       $TARGET"
echo "Remote user:  $REMOTE_USER"
echo "Timestamp:    $(date)"
echo "============================================================"
echo


# ============================================================
# 1. HOST REACHABILITY
# ============================================================

echo "[1] Host Reachability"

if ping -c 1 -W 2 "$TARGET" >/dev/null 2>&1; then
    echo "[PASS] Host is reachable"
else
    echo "[FAIL] Host is not reachable"
fi

echo


# ============================================================
# 2. SSH PORT
# ============================================================

echo "[2] SSH Port"

if nc -z -w 3 "$TARGET" "$SSH_PORT" >/dev/null 2>&1; then
    echo "[PASS] TCP/$SSH_PORT is open"
else
    echo "[FAIL] TCP/$SSH_PORT is closed or unreachable"
fi

echo


# ============================================================
# 3. HTTPS PORT
# ============================================================

echo "[3] HTTPS Port"

if nc -z -w 3 "$TARGET" "$HTTPS_PORT" >/dev/null 2>&1; then
    echo "[PASS] TCP/$HTTPS_PORT is open"
else
    echo "[FAIL] TCP/$HTTPS_PORT is closed or unreachable"
fi

echo


# ============================================================
# 4. COLLECT REMOTE SYSTEM DATA
#    One SSH session = one YubiKey authentication workflow
# ============================================================

echo "[4] Remote System Checks"
echo "[INFO] Authenticating to $REMOTE_USER@$TARGET..."

REMOTE_DATA=$(ssh \
    -i "$SSH_KEY" \
    -p "$SSH_PORT" \
    -o IdentitiesOnly=yes \
    -o ConnectTimeout=5 \
    "$REMOTE_USER@$TARGET" '
        echo "HOSTNAME=$(hostname)"

        echo "SSH_SERVICE=$(systemctl is-active ssh 2>/dev/null)"
        echo "SSH_SOCKET=$(systemctl is-active ssh.socket 2>/dev/null)"
        echo "NGINX_SERVICE=$(systemctl is-active nginx 2>/dev/null)"

        echo "DISK_USAGE=$(df -P / | awk "NR==2 {print \$5}")"

        echo "MEMORY_USAGE=$(free | awk "/Mem:/ {
            printf \"%.0f\", \$3/\$2*100
        }")"

        # Calculate CPU utilization from /proc/stat over one second
        read -r cpu u1 n1 s1 i1 w1 irq1 sirq1 steal1 rest < /proc/stat

        total1=$((u1+n1+s1+i1+w1+irq1+sirq1+steal1))
        idle1=$((i1+w1))

        sleep 1

        read -r cpu u2 n2 s2 i2 w2 irq2 sirq2 steal2 rest < /proc/stat

        total2=$((u2+n2+s2+i2+w2+irq2+sirq2+steal2))
        idle2=$((i2+w2))

        total_delta=$((total2-total1))
        idle_delta=$((idle2-idle1))

        if [ "$total_delta" -gt 0 ]; then
            CPU_USAGE=$(awk -v total="$total_delta" \
                              -v idle="$idle_delta" \
                              "BEGIN {printf \"%.0f\", (1-idle/total)*100}")
        else
            CPU_USAGE=0
        fi

        echo "CPU_USAGE=$CPU_USAGE"
        echo "LOAD_AVG=$(awk "{print \$1}" /proc/loadavg)"
        echo "CPU_CORES=$(nproc)"

	FAILED_SSH_COUNT=$(journalctl -u ssh \
	    --since "24 hours ago" \
	    --no-pager 2>/dev/null |
	    grep -Eci "Failed password|Invalid user|authentication failure")

	echo "FAILED_SSH=$FAILED_SSH_COUNT"

        FIREWALL=$(sudo -n ufw status 2>&1 | head -n 1)
        echo "FIREWALL=$FIREWALL"

        echo "PORTS_BEGIN"
        ss -lnt | awk "NR>1 {print \$4}"
        echo "PORTS_END"
    ' 2>&1)

SSH_RESULT=$?

if [ "$SSH_RESULT" -ne 0 ]; then
    echo "[FAIL] Unable to collect remote system information"
    echo
    echo "SSH output:"
    echo "$REMOTE_DATA"
    echo
    echo "[INFO] Remaining remote checks skipped."
else

    # --------------------------------------------------------
    # Parse remote data
    # --------------------------------------------------------

    REMOTE_HOSTNAME=$(echo "$REMOTE_DATA" |
        awk -F= '/^HOSTNAME=/{print $2}')

    SSH_STATUS=$(echo "$REMOTE_DATA" |
        awk -F= '/^SSH_SERVICE=/{print $2}')

    SSH_SOCKET_STATUS=$(echo "$REMOTE_DATA" |
        awk -F= '/^SSH_SOCKET=/{print $2}')

    NGINX_STATUS=$(echo "$REMOTE_DATA" |
        awk -F= '/^NGINX_SERVICE=/{print $2}')

    DISK_USAGE=$(echo "$REMOTE_DATA" |
        awk -F= '/^DISK_USAGE=/{print $2}')

    MEMORY_USAGE=$(echo "$REMOTE_DATA" |
        awk -F= '/^MEMORY_USAGE=/{print $2}')

    CPU_USAGE=$(echo "$REMOTE_DATA" |
        awk -F= '/^CPU_USAGE=/{print $2}')

    LOAD_AVG=$(echo "$REMOTE_DATA" |
        awk -F= '/^LOAD_AVG=/{print $2}')

    CPU_CORES=$(echo "$REMOTE_DATA" |
        awk -F= '/^CPU_CORES=/{print $2}')

    FAILED_SSH=$(echo "$REMOTE_DATA" |
        awk -F= '/^FAILED_SSH=/{print $2}')

    FIREWALL_STATUS=$(echo "$REMOTE_DATA" |
        sed -n 's/^FIREWALL=//p')


    # ========================================================
    # 5. SERVICES
    # ========================================================

    echo "[PASS] Connected to: ${REMOTE_HOSTNAME:-unknown}"

    if [ "$SSH_STATUS" = "active" ]; then
        echo "[PASS] SSH service is active"
    elif [ "$SSH_SOCKET_STATUS" = "active" ]; then
        echo "[PASS] SSH socket is active"
    else
        echo "[FAIL] SSH service/socket is not active"
    fi

    if [ "$NGINX_STATUS" = "active" ]; then
        echo "[PASS] NGINX service is active"
    else
        echo "[WARN] NGINX service status: ${NGINX_STATUS:-unknown}"
    fi

    echo


    # ========================================================
    # 5. DISK USAGE
    # ========================================================

    echo "[5] Disk Usage"

    DISK_PERCENT="${DISK_USAGE%\%}"

    if [[ "$DISK_PERCENT" =~ ^[0-9]+$ ]]; then

        if [ "$DISK_PERCENT" -ge "$ALERT_DISK" ]; then
            echo "[ALERT] Root filesystem usage: $DISK_USAGE"

        elif [ "$DISK_PERCENT" -ge "$WARN_DISK" ]; then
            echo "[WARN] Root filesystem usage: $DISK_USAGE"

        else
            echo "[PASS] Root filesystem usage: $DISK_USAGE"
        fi

    else
        echo "[WARN] Unable to determine disk usage"
    fi

    echo


    # ========================================================
    # 6. MEMORY USAGE
    # ========================================================

    echo "[6] Memory Usage"

    if [[ "$MEMORY_USAGE" =~ ^[0-9]+$ ]]; then

        if [ "$MEMORY_USAGE" -ge "$ALERT_MEMORY" ]; then
            echo "[ALERT] Memory usage: ${MEMORY_USAGE}%"

        elif [ "$MEMORY_USAGE" -ge "$WARN_MEMORY" ]; then
            echo "[WARN] Memory usage: ${MEMORY_USAGE}%"

        else
            echo "[PASS] Memory usage: ${MEMORY_USAGE}%"
        fi

    else
        echo "[WARN] Unable to determine memory usage"
    fi

    echo


    # ========================================================
    # 7. CPU USAGE
    # ========================================================

    echo "[7] CPU Usage"

    if [[ "$CPU_USAGE" =~ ^[0-9]+$ ]]; then

        if [ "$CPU_USAGE" -ge "$ALERT_CPU" ]; then
            echo "[ALERT] CPU utilization: ${CPU_USAGE}%"

        elif [ "$CPU_USAGE" -ge "$WARN_CPU" ]; then
            echo "[WARN] CPU utilization: ${CPU_USAGE}%"

        else
            echo "[PASS] CPU utilization: ${CPU_USAGE}%"
        fi

        echo "[INFO] 1-minute load average: ${LOAD_AVG:-unknown}"
        echo "[INFO] Logical CPU cores: ${CPU_CORES:-unknown}"

    else
        echo "[WARN] Unable to determine CPU usage"
    fi

    echo


    # ========================================================
    # 8. LISTENING TCP PORTS
    # ========================================================

    echo "[8] Listening TCP Ports"

    echo "$REMOTE_DATA" | awk '
        /PORTS_BEGIN/ {
            capture=1
            next
        }

        /PORTS_END/ {
            capture=0
        }

        capture
    '

    echo


    # ========================================================
    # 9. FAILED SSH LOGINS
    # ========================================================

    echo "[9] Recent Failed SSH Logins"

    if [[ "$FAILED_SSH" =~ ^[0-9]+$ ]]; then

        if [ "$FAILED_SSH" -eq 0 ]; then
            echo "[PASS] No failed SSH authentication attempts in the last 24 hours"

        elif [ "$FAILED_SSH" -lt 5 ]; then
            echo "[WARN] $FAILED_SSH failed SSH authentication attempt(s) in the last 24 hours"

        else
            echo "[ALERT] $FAILED_SSH failed SSH authentication attempts in the last 24 hours"
        fi

    else
        echo "[WARN] Unable to determine failed SSH authentication count"
    fi

    echo


    # ========================================================
    # 10. FIREWALL
    # ========================================================

    echo "[10] Firewall Status"

    if echo "$FIREWALL_STATUS" |
        grep -qi "Status: active"; then

        echo "[PASS] UFW firewall is active"

    elif echo "$FIREWALL_STATUS" |
        grep -qi "Status: inactive"; then

        echo "[WARN] UFW firewall is inactive"

    elif echo "$FIREWALL_STATUS" |
        grep -Eqi "password.*required|a password is required"; then

        echo "[WARN] Cannot determine UFW status without sudo privileges"

    else

        echo "[WARN] Unable to determine firewall status"
        echo "[INFO] Result: ${FIREWALL_STATUS:-no output}"

    fi

    echo
fi


# ============================================================
# 11. TLS CERTIFICATE
# ============================================================

echo "[11] TLS Certificate Expiration"

CERT_END=$(echo |
    openssl s_client \
        -connect "$TARGET:$HTTPS_PORT" \
        -servername "$TLS_SERVER_NAME" \
        2>/dev/null |
    openssl x509 \
        -noout \
        -enddate \
        2>/dev/null |
    cut -d= -f2)

if [ -z "$CERT_END" ]; then

    echo "[FAIL] Unable to retrieve TLS certificate"

else

    CERT_END_EPOCH=$(date -d "$CERT_END" +%s 2>/dev/null)
    NOW_EPOCH=$(date +%s)

    if [ -z "$CERT_END_EPOCH" ]; then

        echo "[FAIL] Unable to parse TLS certificate expiration date"

    else

	DAYS_LEFT=$(( (CERT_END_EPOCH - NOW_EPOCH) / 86400 ))

        if [ "$DAYS_LEFT" -lt 0 ]; then

            echo "[ALERT] TLS certificate has expired"

        elif [ "$DAYS_LEFT" -le "$ALERT_CERT_DAYS" ]; then

            echo "[ALERT] TLS certificate expires in $DAYS_LEFT day(s)"

        elif [ "$DAYS_LEFT" -le "$WARN_CERT_DAYS" ]; then

            echo "[WARN] TLS certificate expires in $DAYS_LEFT day(s)"

        else

            echo "[PASS] TLS certificate expires in $DAYS_LEFT day(s)"

        fi

        echo "[INFO] Certificate expiration: $CERT_END"
    fi
fi

echo


# ============================================================
# COMPLETE
# ============================================================

echo "============================================================"
echo "Health check completed: $(date)"
echo "============================================================"
