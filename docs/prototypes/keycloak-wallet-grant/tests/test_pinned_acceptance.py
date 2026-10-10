"""Contract tests for clean source and mandatory report provenance."""
import importlib.util
from pathlib import Path
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('pinned_acceptance',ROOT/'scripts/pinned_acceptance.py')
assert spec and spec.loader
module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module
spec.loader.exec_module(module)


def test_moving_source_reference_cannot_be_used():
  with pytest.raises(ValueError):module.validate_revision('main')


def test_substituted_equal_count_inventory_is_rejected(tmp_path):
  report=tmp_path/'report.xml'
  report.write_text('<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase classname="A" name="other"/></testsuite>')
  with pytest.raises(ValueError):module.validate_reports([report],{'A.expected'})


def test_skip_cannot_be_a_pass(tmp_path):
  report=tmp_path/'report.xml'
  report.write_text('<testsuite tests="1" failures="0" errors="0" skipped="1"><testcase classname="A" name="expected"><skipped/></testcase></testsuite>')
  with pytest.raises(ValueError):module.validate_reports([report],{'A.expected'})


def test_lie_in_native_counter_is_rejected(tmp_path):
  report=tmp_path/'report.xml'
  report.write_text('<testsuite tests="2" failures="0" errors="0" skipped="0"><testcase classname="A" name="expected"/></testsuite>')
  with pytest.raises(ValueError):module.validate_reports([report],{'A.expected'})


def test_valid_exact_inventory_is_accepted(tmp_path):
  report=tmp_path/'report.xml'
  report.write_text('<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase classname="A" name="expected"/></testsuite>')
  assert module.validate_reports([report],{'A.expected'})==['A.expected']
