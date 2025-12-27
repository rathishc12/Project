import json
from jinja2 import Template
data={
"process":open("output/logs/process_tree.txt").read(),
"fs":open("output/logs/filesystem.diff").read(),
"clamav":open("output/logs/clamav.txt").read(),
"yara":open("output/logs/yara.txt").read(),
"vt":json.dumps(json.load(open("output/logs/virustotal.json")),indent=2)
}
data["exec"] = open("output/logs/exec_commands.txt","r",errors="ignore").read()
html=Template(open("report/template.html").read()).render(**data)
open("output/report.html","w").write(html)
