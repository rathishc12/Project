import os
import hashlib
import requests
import json
import time

API = ""
OUT_JSON = "/output/logs/virustotal.json"
OUT_VERDICT = "/output/logs/virustotal_status.txt"

if not API:
    open(OUT_JSON, "w").write("{}")
    open(OUT_VERDICT, "w").write("SKIPPED")
    exit(0)3

files = set()

# Read changed files from filesystem diff
try:
    with open("/output/logs/filesystem.diff", errors="ignore") as f:
        for line in f:
            if line.startswith("Files"):
                path = line.split(" ")[1]
                if os.path.isfile(path):
                    files.add(path)
except:
    pass

def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

results = {}
malicious = False

for p in files:
    h = sha256(p)
    if not h:
        continue

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{h}",
            headers={"x-apikey": API},
            timeout=15
        )

        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            results[p] = stats

            if stats.get("malicious", 0) > 0:
                malicious = True

        elif r.status_code == 404:
            results[p] = "NOT_FOUND"

        time.sleep(15)  # VT public API rate limit

    except:
        pass

# Write outputs
open(OUT_JSON, "w").write(json.dumps(results, indent=2))

if malicious:
    open(OUT_VERDICT, "w").write("YES")
elif results:
    open(OUT_VERDICT, "w").write("NO")
else:
    open(OUT_VERDICT, "w").write("SKIPPED")
