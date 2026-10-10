#!/usr/bin/env python3
"""Primary-source next-release preflight; blocked is never compatible."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import urllib.request
import xml.etree.ElementTree as ET


def main():
  p=argparse.ArgumentParser();p.add_argument('--report',type=Path,required=True);args=p.parse_args()
  report={'checked_at':datetime.now(timezone.utc).isoformat(),'baseline':'26.8.0','verdict':'blocked','forward_compatibility':'not-tested','sources':{'release_api':'https://api.github.com/repos/keycloak/keycloak/releases/latest','maven_metadata':'https://repo.maven.apache.org/maven2/org/keycloak/keycloak-services/maven-metadata.xml','container_repository':'quay.io/keycloak/keycloak'}}
  try:
    command=subprocess.run(['gh','api','repos/keycloak/keycloak/releases/latest'],capture_output=True,text=True,timeout=30)
    # Avoid dependence on the shell gh wrapper; HTTPS fallback contains no auth.
    if command.returncode:
      request=urllib.request.Request(report['sources']['release_api'],headers={'User-Agent':'decent-keycloak-prototype'})
      with urllib.request.urlopen(request,timeout=30) as response:release=json.load(response)
    else:release=json.loads(command.stdout)
    report['latest_release']=release['tag_name']
    with urllib.request.urlopen(report['sources']['maven_metadata'],timeout=30) as response:metadata=ET.fromstring(response.read())
    report['maven_release']=metadata.findtext('versioning/release')
    baseline=(26,8,0)
    versions=[node.text for node in metadata.findall('versioning/versions/version') if node.text is not None]
    candidates=[v for v in versions if re.fullmatch(r'\d+\.\d+\.\d+',v) and tuple(map(int,v.split('.')))>baseline]
    report['newer_maven_versions']=sorted(candidates,key=lambda x:tuple(map(int,x.split('.'))))
    # No nightly/latest tag is silently substituted for a released candidate.
    candidate=report['latest_release'] if re.fullmatch(r'\d+\.\d+\.\d+',report['latest_release']) and tuple(map(int,report['latest_release'].split('.')))>baseline else '26.8.1'
    report['probed_candidate']=candidate
    probe=subprocess.run(['podman','manifest','inspect','quay.io/keycloak/keycloak:'+candidate],capture_output=True,text=True,timeout=45)
    report['manifest_exit']=probe.returncode
    if probe.returncode:
      report['manifest_failure']='manifest-unknown' if 'manifest unknown' in probe.stderr else 'registry-or-transport-error'
    if candidate in candidates and probe.returncode==0 and report['latest_release']==candidate:
      report['verdict']='candidate-available-not-tested'
    else:report['blocker']='No newer matching released Keycloak Maven API and container candidate established'
  except Exception as exc:report['failure_category']=type(exc).__name__
  args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
  return 0 if report['verdict']=='candidate-available-not-tested' else 2


if __name__=='__main__':raise SystemExit(main())
