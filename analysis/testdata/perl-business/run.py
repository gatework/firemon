#!/usr/bin/env python3
"""Run actual private Perl sources read-only; emit fresh evidence outside the repo."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser()
p.add_argument("--source", type=Path, required=True, help="backend/lib directory containing Firewall/")
p.add_argument("--output", type=Path, required=True, help="new output directory")
args = p.parse_args()
here = Path(__file__).resolve().parent
source = args.source.resolve()
registry = json.loads((here / "source-references.json").read_text())
for entry in registry["sources"]:
    actual = hashlib.sha256((source / entry["path"]).read_bytes()).hexdigest()
    if actual != entry["sha256"]:
        raise SystemExit("reference changed: " + entry["path"])
args.output.mkdir(parents=True, exist_ok=False)
output = args.output.resolve()
if output == here or here in output.parents:
    raise SystemExit("output must be outside the evidence directory")
vendors = ["hillstone", "fortinet", "huawei", "srx", "netscreen", "asa"]
jobs = []
for vendor in vendors:
    for mode in ["search", "convergence", "inspection"]:
        fixture = vendor + ("-convergence" if mode == "convergence" else "") + ".cfg"
        jobs.append((vendor + "-" + mode, mode + ".pl", [vendor], fixture))
for name, script, fixture in [
    ("optimizer", "optimizer.pl", "optimizer-input.json"),
    ("schedules", "schedules.pl", None),
    ("schedule-boundaries", "schedule_boundaries.pl", None),
    ("static-nat", "static_nat.pl", None),
    ("huawei-nat", "huawei_nat.pl", None),
    ("audit", "audit.pl", None),
    ("srx-aliases", "aliases.pl", "srx-alias.cfg"),
]:
    jobs.append((name, script, [], fixture))
for vendor in ["asa", "srx", "netscreen"]:
    jobs.append((vendor + "-usage", "usage.pl", [vendor], vendor + ".cfg"))
for vendor in ["hillstone", "srx", "fortinet", "netscreen", "asa"]:
    jobs.append((vendor + "-dynamic-nat", "dynamic_nat.pl", [vendor], vendor + ".cfg"))
jobs.append(("fortinet-wide-pool", "dynamic_nat.pl", ["fortinet"], "fortinet-wide-pool.cfg"))
for vendor, case in [("asa", "counter-zero"), ("srx", "no-timestamp"), ("netscreen", "missing-ports")]:
    name = vendor + "-" + case
    jobs.append((name, "usage_edges.pl", [vendor, name], vendor + ".cfg"))
statuses = []
for name, script, argv, fixture in jobs:
    command = ["docker", "run", "--rm", "-i", "--network=none", "--read-only",
               "--tmpfs", "/tmp:rw,noexec,nosuid,size=1m", "--tmpfs", "/wls:rw,noexec,nosuid,size=1m",
               "--mount", f"type=bind,src={source},dst=/source,readonly",
               "--mount", f"type=bind,src={here},dst=/oracle,readonly",
               "-e", "TZ=UTC", "--entrypoint", "perl", registry["image"],
               "-I/source", "/oracle/" + script, *argv]
    result = subprocess.run(command, input=(here / fixture).read_bytes() if fixture else b"",
                            capture_output=True, timeout=90, check=False)
    (output / (name + ".json")).write_bytes(result.stdout)
    (output / (name + ".stderr")).write_bytes(result.stderr)
    statuses.append({"name": name, "exit": result.returncode,
                     "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                     "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
    print(name, result.returncode, flush=True)
(output / "runs.json").write_text(json.dumps(statuses, indent=2) + "\n")
if any(run["exit"] for run in statuses):
    raise SystemExit(1)
