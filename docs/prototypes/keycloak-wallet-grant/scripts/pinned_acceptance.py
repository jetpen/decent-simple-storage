#!/usr/bin/env python3
"""Clean revision-pinned prototype acceptance with exact native test inventory."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]


def validate_revision(value):
  if not re.fullmatch(r'[0-9a-f]{40}',value):raise ValueError('full immutable source revision required')
  return value


def validate_candidate(version,image):
  if version is None and image is None:return None
  if version is None or image is None:raise ValueError('candidate version and digest required together')
  if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',version):raise ValueError('released numeric version required')
  if not re.fullmatch(r'quay\.io/keycloak/keycloak@sha256:[0-9a-f]{64}',image):raise ValueError('official immutable candidate image required')
  return {'version':version,'image':image,'forward_upgrade':tuple(map(int,version.split('.')))>(26,8,0)}


def compatibility_scope(candidate, *, passed):
  """A fresh database run cannot certify a deployment migration strategy."""
  return {
    'fresh_start_conformance':'passed' if passed else 'not-established',
    'forward_release_fresh_start':('passed' if passed else 'not-established') if candidate and candidate['forward_upgrade'] else 'not-tested',
    'persisted_state_migration':'not-tested',
    'mixed_version_rolling':'not-tested',
    'rollback_restore':'not-tested',
    'optimized_startup':'not-tested',
  }


def validate_reports(paths,expected):
  found=[]
  for path in paths:
    suite=ET.parse(path).getroot()
    if suite.tag!='testsuite':raise ValueError('unsupported native report wrapper')
    cases=suite.findall('testcase')
    counters={'tests':len(cases),'failures':0,'errors':0,'skipped':0}
    for case in cases:
      identity=case.attrib['classname']+'.'+case.attrib['name']
      if identity in found:raise ValueError('duplicate test identity')
      found.append(identity)
      outcomes=[child.tag for child in case if child.tag in ('failure','error','skipped')]
      if len(outcomes)>1:raise ValueError('contradictory outcomes')
      if outcomes:
        counters[{'failure':'failures','error':'errors','skipped':'skipped'}[outcomes[0]]]+=1
    for key,value in counters.items():
      if int(suite.attrib[key])!=value:raise ValueError('native report counter mismatch')
    if any(counters[k] for k in ('failures','errors','skipped')):raise ValueError('mandatory test did not pass')
  if set(found)!=set(expected):raise ValueError('mandatory inventory mismatch')
  return sorted(found)


def command(args,**kwargs):
  result=subprocess.run(args,capture_output=True,**kwargs)
  if result.returncode:raise RuntimeError('acceptance prerequisite command failed')
  return result.stdout


def export_source(repository,revision,destination):
  validate_revision(revision)
  actual=command(['git','-C',str(repository),'rev-parse',revision+'^{commit}']).decode().strip()
  if actual!=revision:raise ValueError('source identity mismatch')
  archive=command(['git','-C',str(repository),'archive','--format=tar',revision])
  destination.mkdir()
  with tarfile.open(fileobj=io.BytesIO(archive)) as tar:tar.extractall(destination,filter='data')
  return hashlib.sha256(archive).hexdigest()


def main():
  parser=argparse.ArgumentParser()
  parser.add_argument('--source-revision',required=True)
  parser.add_argument('--candidate-version')
  parser.add_argument('--candidate-image')
  parser.add_argument('--force-preflight-failure',action='store_true',help='exercise failed live gate and cleanup without a passing receipt')
  parser.add_argument('--report-dir',type=Path,required=True)
  args=parser.parse_args();validate_revision(args.source_revision)
  candidate=validate_candidate(args.candidate_version,args.candidate_image)
  args.report_dir.mkdir(parents=True,exist_ok=True)
  receipt_path=args.report_dir/'receipt.json'
  receipt_path.unlink(missing_ok=True)
  env=dict(os.environ)
  for key in list(env):
    if key.startswith(('KC_','VERIFIER_','REGISTRY_')) or key in ('PYTEST_ADDOPTS','PYTHONPATH','MAVEN_OPTS','JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS'):env.pop(key,None)
  receipt={'schema':1,'profile':'pinned-live-prototype','verdict':'failed','sources':{},'limits':['Not bit-identical/hermetic: apt repository, Maven transitive artifacts, host Java/Maven and registry availability remain external.','No production deployment or partition/failure guarantee.']}
  if candidate:receipt['candidate']=candidate
  with tempfile.TemporaryDirectory(prefix='pinned-kc-',dir=os.environ['TMPDIR']) as directory:
    workspace=Path(directory)
    try:
      projects=workspace/'projects';projects.mkdir()
      # Read the build policy from the executed storage revision, not the moving worktree.
      export_source(Path('/home/ben/projects/decent-simple-storage'),args.source_revision,projects/'decent-simple-storage')
      prototype=projects/'decent-simple-storage/docs/prototypes/keycloak-wallet-grant'
      policy=json.loads((prototype/'build/pinned-inputs.json').read_text())
      receipt['sources']['decent-simple-storage']=args.source_revision
      for name,revision in policy['sources'].items():
        receipt['sources'][name]=validate_revision(revision)
        export_source(Path('/home/ben/projects')/name,revision,projects/name)
      lock=prototype/'build/python-requirements.lock'
      receipt['python_lock_sha256']=hashlib.sha256(lock.read_bytes()).hexdigest()
      # An isolated environment uses the same hash-locked third-party versions as images.
      venv=workspace/'host-venv'
      command(['uv','venv','--python','3.12',str(venv)],env=env)
      python=venv/'bin/python'
      command(['uv','pip','install','--python',str(python),'--require-hashes','-r',str(lock)],env=env,timeout=240)
      command(['uv','pip','install','--python',str(python),'--no-deps','--no-build-isolation',str(projects/'decent-registry'),str(projects/'decent-identity')],env=env,timeout=90)
      command(['uv','pip','check','--python',str(python)],env=env)
      env.update(KC_REGISTRY_ROOT=str(projects/'decent-registry'),KC_IDENTITY_ROOT=str(projects/'decent-identity'),KC_BUILD_CONTEXT=str(projects),KC_HELPER_PYTHON=str(python),KC_TEST_REPORT_DIR=str(args.report_dir))
      if args.force_preflight_failure:env['REGISTRY_LISTEN_HOST']='registry'
      for key,value in policy['images'].items():env['KC_'+key.upper()+'_BASE']=value
      if candidate:
        # Build the extension against candidate APIs, but don't rewrite the
        # archived sources or silently change its baseline lock policy.
        command(['podman','pull',candidate['image']],env=env,timeout=180)
        actual=command(['podman','run','--rm',candidate['image'],'--version'],env=env,timeout=60).decode()
        if not re.search(r'Keycloak\s+'+re.escape(candidate['version'])+r'(?:\s|$)',actual):raise ValueError('candidate runtime version mismatch')
        env['KC_KEYCLOAK_BASE']=candidate['image']
        env['KC_API_VERSION']=candidate['version']
      command([str(python),'-m','pytest','-q','tests','--junitxml='+str(args.report_dir/'python.xml')],cwd=prototype,env=env,timeout=90)
      # A disposable key is generated by the live runner, never supplied externally.
      with subprocess.Popen([str(prototype/'scripts/run-podman-cluster-test.sh')],cwd=prototype,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True) as process:
        try:status=process.wait(timeout=420)
        except subprocess.TimeoutExpired:
          os.killpg(process.pid,signal.SIGTERM)
          try:process.wait(timeout=30)
          except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
          raise RuntimeError('live acceptance timed out; no passing receipt')
      if status:raise RuntimeError('live acceptance or cleanup failed')
      inventory=json.loads((prototype/'build/mandatory-tests.json').read_text())
      native=[args.report_dir/'python.xml']+list((prototype/'target/surefire-reports').glob('TEST-*.xml'))+list((prototype/'target/failsafe-reports').glob('TEST-*.xml'))
      # pytest uses a testsuites wrapper; convert while preserving inner native counters.
      tree=ET.parse(args.report_dir/'python.xml')
      if tree.getroot().tag=='testsuites':
        suites=tree.getroot().findall('testsuite')
        if len(suites)!=1:raise ValueError('unexpected Python report suites')
        ET.ElementTree(suites[0]).write(args.report_dir/'python-suite.xml');native[0]=args.report_dir/'python-suite.xml'
      receipt['mandatory_passed']=validate_reports(native,set(inventory))
      for gate in ('preflight','transport','cluster','rotation'):
        evidence=json.loads((args.report_dir/(gate+'.json')).read_text())
        if evidence.get('status')!='passed' and evidence.get('passed') is not True:raise ValueError('missing or failed live gate')
      if (args.report_dir/'cleanup.txt').read_text().strip()!='original_exit=0 cleanup_failed=0':raise ValueError('cleanup not verified')
      receipt['images']=json.loads((args.report_dir/'images.json').read_text())
      receipt['verdict']='passed'
      if candidate:receipt['candidate']['verdict']='passed'
    except Exception as exc:
      receipt['failure_category']=type(exc).__name__
  receipt['workspace_removed']=not workspace.exists()
  if not receipt['workspace_removed']:receipt['verdict']='failed'
  receipt['compatibility_scope']=compatibility_scope(candidate,passed=receipt['verdict']=='passed')
  receipt_path.write_text(json.dumps(receipt,indent=2)+'\n')
  print(json.dumps({'verdict':receipt['verdict'],'mandatory_count':len(receipt.get('mandatory_passed',[])),'workspace_removed':receipt['workspace_removed'],'failure_category':receipt.get('failure_category')}))
  return 0 if receipt['verdict']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
