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


@pytest.mark.parametrize('candidate', [None, {'forward_upgrade':False}, {'forward_upgrade':True}])
def test_fresh_start_success_never_claims_deployment_upgrade_safety(candidate):
  scope=module.compatibility_scope(candidate,passed=True)
  assert scope['fresh_start_conformance']=='passed'
  assert scope['persisted_state_migration']=='not-tested'
  assert scope['mixed_version_rolling']=='not-tested'
  assert scope['rollback_restore']=='not-tested'
  assert scope['optimized_startup']=='not-tested'
  assert scope['forward_release_fresh_start']==('passed' if candidate and candidate['forward_upgrade'] else 'not-tested')
  assert 'upgrade_compatibility' not in scope


def test_failed_candidate_cannot_claim_conformance():
  scope=module.compatibility_scope({'forward_upgrade':True},passed=False)
  assert scope['fresh_start_conformance']=='not-established'
  assert scope['forward_release_fresh_start']=='not-established'
