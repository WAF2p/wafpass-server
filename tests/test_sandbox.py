"""Tests for the sandbox router helpers."""
from __future__ import annotations

from types import SimpleNamespace

import pytest


@pytest.fixture
def fake_control_result():
    """Return a minimal fake control result."""
    control = SimpleNamespace(
        id="WAF-SEC-001",
        title="S3 Block Public Access",
        pillar="security",
        severity="high",
        category="storage",
        description="desc",
        rationale="rationale",
        threat=["t1"],
        regulatory_mapping=[{"framework": "CIS", "controls": ["2.1"]}],
        checks=[],
    )
    result = SimpleNamespace(
        check_id="WAF-SEC-001-01",
        check_title="Public access block enabled",
        control_id="WAF-SEC-001",
        severity="high",
        status="FAIL",
        resource="aws_s3_bucket.example",
        message="Public access is not blocked",
        remediation="Set block_public_policy = true",
        example={"compliant": "true", "non_compliant": "false"},
        regulatory_mapping=[{"framework": "CIS", "controls": ["2.1"]}],
    )
    return SimpleNamespace(control=control, results=[result])


def test_build_demo_result_shape(fake_control_result):
    """_build_demo_result should return a valid wafpass-result schema."""
    from wafpass_server.routers.sandbox import _build_demo_result

    result = _build_demo_result(
        raw_results=[fake_control_result],
        controls=[fake_control_result.control],
        scan_dir="/tmp/demo-scan",
        bucket_name="wafpass-demo-test",
    )

    assert result.project == "wafpass-demo"
    assert result.branch == "main"
    assert result.stage == "demo"
    assert result.iac_framework == "terraform"
    assert result.path == "/tmp/demo-scan"
    assert result.controls_loaded == 1
    assert result.controls_run == 1
    assert len(result.findings) == 1
    assert result.findings[0].status == "FAIL"
    assert result.findings[0].control_id == "WAF-SEC-001"
    assert len(result.controls_meta) == 1
    assert "main.tf" in result.source_snapshot
