#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo ./analyze.sh <target>)"
  exit 1
fi

TARGET="${1:-}"

if [ -z "$TARGET" ]; then
  echo "Usage: sudo ./analyze.sh <target>"
  exit 1
fi

IMAGE=linux-sandbox
CONTAINER=sandbox-$(date +%s)

mkdir -p output/logs output/pcaps

echo "[+] Building sandbox image"
docker build -t "$IMAGE" .

echo "[+] Running analysis for 15 minutes"
docker run --name "$CONTAINER" \
  --privileged \
  --env-file .env \
  -v "$(pwd)/output:/output" \
  -v "$(pwd)/config:/config" \
  -v "$(pwd):/host" \
  -v "$(pwd)/config/yara:/config/yara:ro" \
  "$IMAGE" "$TARGET"

echo "[+] Generating report"
python3 report/generate_report.py || true

echo "[+] Virus Total lookup (input + change files)"
export SANDBOX_INPUT="$INPUT"

python3 /vt/vt_check.py || true


echo "[+] Scheduling cleanup after 24h"
(
  sleep 86400
  docker rm -f "$CONTAINER" 2>/dev/null || true
  docker rmi "$IMAGE" 2>/dev/null || true
) &

echo "[✔] Done. Report at output/report.html"
