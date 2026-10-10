"""Upgrade gates must distinguish a real upgrade from a baseline rerun."""
import pytest
from test_pinned_acceptance import module


def test_candidate_tag_cannot_replace_digest_identity():
  with pytest.raises(ValueError):module.validate_candidate('26.8.1','quay.io/keycloak/keycloak:26.8.1')


def test_unpaired_candidate_inputs_are_rejected():
  with pytest.raises(ValueError):module.validate_candidate('26.8.1',None)


def test_baseline_candidate_is_not_a_forward_upgrade():
  result=module.validate_candidate('26.8.0','quay.io/keycloak/keycloak@sha256:'+'a'*64)
  assert result['forward_upgrade'] is False


def test_newer_candidate_is_explicitly_forward():
  result=module.validate_candidate('26.8.1','quay.io/keycloak/keycloak@sha256:'+'a'*64)
  assert result['forward_upgrade'] is True
