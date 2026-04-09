"""
블랙박스 검사 - RTSP/ONVIF 프로토콜 인증 검사기 단위 테스트
"""

from unittest.mock import patch

import pytest

from src.engines.blackbox.protocol_auth import ProtocolAuthChecker
from src.models import TestStatus


@pytest.fixture
def checker():
    return ProtocolAuthChecker(
        host="192.168.1.100",
        rtsp_port=554,
        http_port=80,
        has_rtsp=True,
        has_onvif=True,
    )


@pytest.fixture
def checker_no_rtsp():
    return ProtocolAuthChecker(
        host="192.168.1.100",
        has_rtsp=False,
        has_onvif=False,
    )


class TestRTSPAuth:
    """RTSP 인증 검사 테스트"""

    def test_pass_when_401_returned(self, checker):
        """RTSP DESCRIBE 요청에 401이 반환되면 PASS여야 한다."""
        with patch.object(checker, "_send_rtsp_describe", return_value="RTSP/1.0 401 Unauthorized\r\n\r\n"):
            result = checker.check_rtsp_auth()
        assert result.status == TestStatus.PASS

    def test_fail_when_200_returned(self, checker):
        """인증 없이 200이 반환되면 FAIL이어야 한다."""
        with patch.object(checker, "_send_rtsp_describe", return_value="RTSP/1.0 200 OK\r\n\r\n"):
            result = checker.check_rtsp_auth()
        assert result.status == TestStatus.FAIL

    def test_skip_when_rtsp_disabled(self, checker_no_rtsp):
        """RTSP 비활성화 시 SKIP이어야 한다."""
        result = checker_no_rtsp.check_rtsp_auth()
        assert result.status == TestStatus.SKIP

    def test_error_on_connection_failure(self, checker):
        """연결 실패 시 ERROR이어야 한다."""
        with patch.object(checker, "_send_rtsp_describe", return_value="ERROR: refused"):
            result = checker.check_rtsp_auth()
        assert result.status == TestStatus.ERROR

    def test_result_id(self, checker):
        """결과 ID가 AUTH-008이어야 한다."""
        with patch.object(checker, "_send_rtsp_describe", return_value="RTSP/1.0 401 Unauthorized\r\n\r\n"):
            result = checker.check_rtsp_auth()
        assert result.id == "AUTH-008"


class TestDigestStrength:
    """Digest 알고리즘 강도 검사 테스트"""

    def test_fail_when_md5_used(self, checker):
        """MD5 Digest 사용 시 FAIL이어야 한다."""
        response = 'RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest algorithm="MD5"\r\n\r\n'
        with patch.object(checker, "_send_rtsp_describe", return_value=response):
            result = checker.check_rtsp_digest_strength()
        assert result.status == TestStatus.FAIL

    def test_pass_when_sha256_used(self, checker):
        """SHA-256 Digest 사용 시 PASS이어야 한다."""
        response = 'RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest algorithm="SHA-256"\r\n\r\n'
        with patch.object(checker, "_send_rtsp_describe", return_value=response):
            result = checker.check_rtsp_digest_strength()
        assert result.status == TestStatus.PASS


class TestONVIFAuth:
    """ONVIF 인증 검사 테스트"""

    def test_skip_when_onvif_disabled(self, checker_no_rtsp):
        """ONVIF 비활성화 시 SKIP이어야 한다."""
        result = checker_no_rtsp.check_onvif_auth()
        assert result.status == TestStatus.SKIP

    def test_result_id(self, checker):
        """결과 ID가 AUTH-007이어야 한다."""
        result = checker.check_onvif_auth()
        assert result.id == "AUTH-007"
