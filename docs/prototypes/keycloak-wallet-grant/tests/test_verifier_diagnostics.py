import pytest
from fastapi.testclient import TestClient
from test_verifier_runtime import module
from test_verifier import configured, grant


@pytest.mark.parametrize('failure,category', [
  (TimeoutError('sensitive transport details'), 'timeout'),
  (OSError('sensitive transport details'), 'transport'),
  (module.IdentityHistoryUnavailable('sensitive history details'), 'history_unavailable'),
  (RuntimeError('sensitive runtime details'), 'runtime'),
])
def test_safe_internal_failure_category(monkeypatch, caplog, failure, category):
  configured(monkeypatch)

  async def fail(**kwargs):
    raise failure

  monkeypatch.setattr(module, 'resolve_identity_record', fail)
  with caplog.at_level('WARNING'), TestClient(module.app) as client:
    response = client.post('/v1/verify-grant', json=grant())
  assert response.status_code == 503
  assert response.json()['detail'] == 'current Identity state unavailable'
  assert f'category={category}' in caplog.text
  assert 'sensitive' not in caplog.text
  assert 'alice' not in caplog.text
