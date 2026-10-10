#!/usr/bin/env python3
"""Assert both pinned Keycloak nodes report the same two-member cluster view."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--node', action='append', required=True)
parser.add_argument('--report', type=Path, required=True)
args = parser.parse_args()
assert len(args.node) == 2
views = {}
deadline = time.monotonic() + 60
while time.monotonic() < deadline:
  for node in args.node:
    process = subprocess.run(['podman','logs',node],capture_output=True,text=True,timeout=10)
    matches = re.findall(r'ISPN000094: Received new cluster view for channel ISPN: (\[[^\]]+\]) \(2\) \[([^\]]+)\]',process.stdout+'\n'+process.stderr)
    if matches:
      view, members = matches[-1]
      views[node] = {'view':view, 'members': sorted(x.strip() for x in members.split(','))}
  if len(views)==2 and len(views[args.node[0]]['members'])==2 and views[args.node[0]]==views[args.node[1]]:
    break
  time.sleep(.5)
passed = len(views)==2 and len(views[args.node[0]]['members'])==2 and views[args.node[0]]==views[args.node[1]]
args.report.write_text(json.dumps({'passed':passed,'nodes':views},indent=2)+'\n')
print(json.dumps({'cluster_membership_verified':passed}))
raise SystemExit(0 if passed else 1)
