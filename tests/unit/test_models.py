from datetime import datetime, timezone
import pytest
from epitaph.models.base import DetectionStatus, ExecutionType, ProxyProtocol
from epitaph.models.proxy import ProxyEntity
from epitaph.models.result import CheckResult, ScanSessionResult
from epitaph.models.target import TargetProfile


def test_target_profile_fields() -> None:
    target = TargetProfile(username="alex_dev", metadata={"source": "cli"})
    assert target.username == "alex_dev"
    assert target.metadata["source"] == "cli"


def test_proxy_entity_url() -> None:
    p1 = ProxyEntity(host="127.0.0.1", port=8080, protocol=ProxyProtocol.HTTP)
    assert p1.url == "http://127.0.0.1:8080"

    p2 = ProxyEntity(
        host="proxy.org",
        port=9050,
        protocol=ProxyProtocol.SOCKS5,
        username="user",
        password="pwd",
    )
    assert p2.url == "socks5h://user:pwd@proxy.org:9050"


def test_scan_session_result_aggregation() -> None:
    target = TargetProfile(username="target_user")
    now = datetime.now(timezone.utc)
    res1 = CheckResult(
        platform_name="GitHub",
        target=target,
        status=DetectionStatus.FOUND,
        execution_type=ExecutionType.HTTP,
    )
    res2 = CheckResult(
        platform_name="Steam",
        target=target,
        status=DetectionStatus.NOT_FOUND,
        execution_type=ExecutionType.BROWSER,
    )

    session = ScanSessionResult(
        session_id="test1234",
        target=target,
        start_time=now,
        end_time=now,
        results=[res1, res2],
    )
    assert session.total_scanned == 2
    assert session.found_count == 1
