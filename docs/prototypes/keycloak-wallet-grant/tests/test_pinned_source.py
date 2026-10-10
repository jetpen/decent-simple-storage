"""Ensure committed archives ignore dirty/untracked checkout inputs."""
import subprocess
from test_pinned_acceptance import module


def test_source_archive_excludes_uncommitted_and_untracked_files(tmp_path):
  repository=tmp_path/'repo';repository.mkdir()
  def git(*args):
    return subprocess.check_output(['git','-C',str(repository),*args],text=True).strip()
  git('init','-q')
  (repository/'fixture.txt').write_text('committed')
  git('add','fixture.txt')
  git('-c','user.name=Fixture','-c','user.email=fixture@example.test','commit','-qm','fixture')
  revision=git('rev-parse','HEAD')
  (repository/'fixture.txt').write_text('dirty')
  (repository/'untracked.txt').write_text('ignored')
  exported=tmp_path/'export'
  module.export_source(repository,revision,exported)
  assert (exported/'fixture.txt').read_text()=='committed'
  assert not (exported/'untracked.txt').exists()


def test_duplicate_native_case_is_rejected(tmp_path):
  report=tmp_path/'report.xml'
  report.write_text('<testsuite tests="2" failures="0" errors="0" skipped="0"><testcase classname="A" name="expected"/><testcase classname="A" name="expected"/></testsuite>')
  import pytest
  with pytest.raises(ValueError):module.validate_reports([report],{'A.expected'})


def test_failure_cannot_be_hidden_by_skipped_outcome(tmp_path):
  report=tmp_path/'report.xml'
  report.write_text('<testsuite tests="1" failures="0" errors="0" skipped="1"><testcase classname="A" name="expected"><skipped/><failure/></testcase></testsuite>')
  import pytest
  with pytest.raises(ValueError):module.validate_reports([report],{'A.expected'})
