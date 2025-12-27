#!/bin/bash
set -euo pipefail

# ==============================
# CONFIG
# ==============================
TARGET="${1:-}"
HOST_TARGET="/host/$TARGET"

OUT="/output"
LOG="$OUT/logs"
ART="$OUT/artifacts"
PCAP="$OUT/pcaps"

RUNTIME=900   # 15 minutes

mkdir -p "$LOG" "$ART" "$PCAP"

# ==============================
# INTERACTIVE GUARD
# ==============================
if [[ -z "$TARGET" || "$TARGET" == "bash" ]]; then
    echo "[*] Interactive shell requested"
    exec bash
fi

if [[ ! -f "$HOST_TARGET" ]]; then
    echo "[!] Target not found: $HOST_TARGET"
    exit 1
fi

echo "[+] Analyzing sample: $TARGET"

# ==============================
# STATIC ANALYSIS
# ==============================
echo "[+] Static analysis"
{
    echo "==== HASHES ===="
    sha256sum "$HOST_TARGET"
    md5sum "$HOST_TARGET"

    echo -e "\n==== FILE TYPE ===="
    file "$HOST_TARGET"

    echo -e "\n==== STRINGS (HEAD) ===="
    strings -a "$HOST_TARGET" | head -200

    echo -e "\n==== URLs / IPs ===="
    strings "$HOST_TARGET" | grep -Eo '(http|https)://[^ ]+|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u
} > "$LOG/static.txt"

# ==============================
# FILESYSTEM SNAPSHOT (BEFORE)
# ==============================
echo "[+] Filesystem snapshot BEFORE"
find /tmp /etc /usr -type f -printf "%p %s\n" | sort > /tmp/fs_before.txt

# ==============================
# NETWORK DECEPTION
# ==============================
echo "[+] Enabling network deception"

# Block real outbound traffic
iptables -P OUTPUT DROP
iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT

# Fake DNS resolver
echo "nameserver 127.0.0.1" > /etc/resolv.conf

python3 - << 'EOF' > /output/logs/dns.log 2>&1 &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 53))
while True:
    data, addr = s.recvfrom(512)
    print("[DNS] Query from", addr)
    s.sendto(data[:2] + b"\x81\x80" + data[4:6] + data[4:6] + b"\x00\x00\x00\x00" + data[12:], addr)
EOF
DNS_PID=$!

# Fake HTTP C2
python3 -m http.server 80 --bind 0.0.0.0 > "$LOG/http.log" 2>&1 &
HTTP_PID=$!

# ==============================
# NETWORK CAPTURE
# ==============================
echo "[+] Starting network capture"
tcpdump -i any -w "$PCAP/network.pcap" &
TCP_PID=$!

# ==============================
# DETONATION + SYSCALL TRACE
# ==============================
echo "[+] Executing sample with syscall tracing"
chmod +x "$HOST_TARGET"

timeout "$RUNTIME" \
strace -ff -tt \
-o "$LOG/syscalls" \
bash "$HOST_TARGET" \
> "$LOG/runtime.log" 2>&1 || true

echo "[+] Observation window"
sleep "$RUNTIME"

# ==============================
# STOP BACKGROUND SERVICES
# ==============================
kill $TCP_PID $DNS_PID $HTTP_PID 2>/dev/null || true

# ==============================
# FILESYSTEM SNAPSHOT (AFTER)
# ==============================
echo "[+] Filesystem snapshot AFTER"
find /tmp /etc /usr -type f -printf "%p %s\n" | sort > /tmp/fs_after.txt
diff -u /tmp/fs_before.txt /tmp/fs_after.txt > "$LOG/filesystem.diff" || true

# ==============================
# EXTRACT DROPPED FILES
# ==============================
echo "[+] Extracting dropped artifacts"
awk '/^\+\/(tmp|etc|usr)/ {print $1}' "$LOG/filesystem.diff" \
| sed 's/^+//' \
| while read -r f; do
    cp --parents "$f" "$ART" 2>/dev/null || true
done

# ==============================
# HASH ARTIFACTS
# ==============================
echo "[+] Hashing artifacts"
find "$ART" -type f -exec sha256sum {} \; > "$LOG/artifact_hashes.txt"

# ==============================
# SYSCALL DETECTION
# ==============================
echo "[+] Analyzing syscalls"

SYSCALL_FILES=$(ls "$LOG"/syscalls.* 2>/dev/null || true)

if [[ -n "$SYSCALL_FILES" ]]; then
    grep -E "execve|connect|chmod|chown|unlink|ptrace" $SYSCALL_FILES \
        > "$LOG/syscall_alerts.txt" || true
else
    echo "[!] No syscall trace files produced" > "$LOG/syscall_alerts.txt"
fi

# ==============================
# CLAMAV SCAN (CORRECT SCOPE)
# ==============================
echo "[+] ClamAV scan"
clamscan -r /tmp /output /host \
  --infected \
  --log="$LOG/clamav.txt" || true

# ==============================
# YARA SCAN
# ==============================
echo "[+] YARA scan (source rules)"

YARA_RULES="/config/yara/index.yar"
TARGETS=()

if [[ -n "$INPUT" && -f "/host/$INPUT" ]]; then
    TARGETS+=("/host/$INPUT")
fi

TARGETS+=("/tmp" "/output")

if [[ -f "$YARA_RULES" ]]; then
    yara -w "$YARA_RULES" "${TARGETS[@]}" \
        > "$LOG/yara.txt" 2> "$LOG/yara_errors.txt" || true
else
    echo "YARA rules not found" > "$LOG/yara_errors.txt"
fi

# YARA verdict
if [[ -s "$LOG/yara_errors.txt" ]]; then
    echo "ERROR" > "$LOG/yara_status.txt"
elif [[ -s "$LOG/yara.txt" ]]; then
    echo "YES" > "$LOG/yara_status.txt"
else
    echo "NO" > "$LOG/yara_status.txt"
fi
    
# ==============================
# NETWORK IOC EXTRACTION
# ==============================
echo "[+] Extracting network IOCs"
tcpdump -nn -r "$PCAP/network.pcap" > "$LOG/network_iocs.txt" || true

# ==============================
# BEHAVIOR SCORING
# ==============================
echo "[+] Calculating behavior score"
score=0

grep -q execve "$LOG/syscall_alerts.txt" && ((score+=2))
grep -q connect "$LOG/syscall_alerts.txt" && ((score+=3))
grep -q EICAR "$LOG/clamav.txt" && ((score+=5))
grep -q HTTP "$LOG/network_iocs.txt" && ((score+=3))

{
    echo "Risk Score: $score"
    if (( score >= 9 )); then
        echo "Verdict: HIGH-RISK MALWARE"
    elif (( score >= 6 )); then
        echo "Verdict: MALICIOUS"
    elif (( score >= 3 )); then
        echo "Verdict: SUSPICIOUS"
    else
        echo "Verdict: BENIGN"
    fi
} > "$LOG/score.txt"

# ==============================
# DONE
# ==============================
echo "[✔] Sandbox execution completed"
exec bash
