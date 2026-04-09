"""
블랙박스 검사 - TLS 검사기 단위 테스트
"""

import ssl
from unittest.mock import MagicMock, patch

import pytest

from src.engines.blackbox.tls_checker import TLSChecker
from src.models import TestStatus


@pytest.fixture
def checker():
    return TLSChecker(host="192.168.1.100", port=443)


class TestTLSVersionCheck:
    """TLS 버전 검사 테스트"""

    def test_pass_when_tls12(self, checker):
        """TLS 1.2 협상 시 PASS를 반환해야 한다."""
        mock_info = {"protocol": "TLSv1.2", "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.2", 256)}
        with patch.object(checker, "_get_tls_info", return_value=mock_info):
            result = checker.check_tls_version()
        assert result.status == TestStatus.PASS
        assert "TLSv1.2" in result.details

    def test_pass_when_tls13(self, checker):
        """TLS 1.3 협상 시 PASS를 반환해야 한다."""
        mock_info = {"protocol": "TLSv1.3", "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)}
        with patch.object(checker, "_get_tls_info", return_value=mock_info):
            result = checker.check_tls_version()
        assert result.status == TestStatus.PASS

    def test_fail_when_tls10(self, checker):
        """TLS 1.0 협상 시 FAIL을 반환해야 한다."""
        mock_info = {"protocol": "TLSv1", "cipher": ("AES128-SHA", "TLSv1", 128)}
        with patch.object(checker, "_get_tls_info", return_value=mock_info):
            result = checker.check_tls_version()
        assert result.status == TestStatus.FAIL

    def test_error_when_connection_fails(self, checker):
        """연결 실패 시 ERROR를 반환해야 한다."""
        with patch.object(checker, "_get_tls_info", return_value=None):
            result = checker.check_tls_version()
        assert result.status == TestStatus.ERROR

    def test_result_has_correct_id(self, checker):
        """결과의 ID가 CRYPT-001이어야 한다."""
        with patch.object(checker, "_get_tls_info", return_value=None):
            result = checker.check_tls_version()
        assert result.id == "CRYPT-001"


class TestWeakTLSRejection:
    """취약 TLS 버전 거부 검사 테스트"""

    def test_pass_when_tls10_rejected(self, checker):
        """TLS 1.0 연결이 거부되면 PASS를 반환해야 한다."""
        with patch("socket.create_connection", side_effect=ssl.SSLError("rejected")):
            result = checker.check_weak_tls_rejected()
        assert result.status == TestStatus.PASS

    def test_result_id(self, checker):
        """결과의 ID가 CRYPT-002이어야 한다."""
        with patch("socket.create_connection", side_effect=OSError("refused")):
            result = checker.check_weak_tls_rejected()
        assert result.id == "CRYPT-002"


class TestCipherSuites:
    """암호 스위트 검사 테스트"""

    def test_fail_when_rc4_used(self, checker):
        """RC4가 포함된 암호 스위트면 FAIL을 반환해야 한다."""
        mock_info = {
            "protocol": "TLSv1.2",
            "cipher": ("RC4-SHA", "TLSv1.2", 128),
        }
        with patch.object(checker, "_get_tls_info", return_value=mock_info):
            result = checker.check_cipher_suites()
        assert result.status == TestStatus.FAIL

    def test_pass_when_ecdhe_used(self, checker):
        """ECDHE가 포함된 암호 스위트면 PASS를 반환해야 한다."""
        mock_info = {
            "protocol": "TLSv1.3",
            "cipher": ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256),
        }
        with patch.object(checker, "_get_tls_info", return_value=mock_info):
            result = checker.check_cipher_suites()
        assert result.status == TestStatus.PASS

    def test_error_when_no_connection(self, checker):
        """연결 실패 시 ERROR를 반환해야 한다."""
        with patch.object(checker, "_get_tls_info", return_value=None):
            result = checker.check_cipher_suites()
        assert result.status == TestStatus.ERROR


class TestTLSCheckerRun:
    """TLSChecker.run() 통합 테스트"""

    def test_run_returns_three_results(self, checker):
        """run()은 3개의 결과를 반환해야 한다."""
        mock_info = {"protocol": "TLSv1.3", "cipher": ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)}
        with (
            patch.object(checker, "_get_tls_info", return_value=mock_info),
            patch("socket.create_connection", side_effect=ssl.SSLError("rejected")),
        ):
            results = checker.run()
        assert len(results) == 3

    def test_run_all_have_engine_blackbox(self, checker):
        """모든 결과의 엔진이 blackbox여야 한다."""
        with patch.object(checker, "_get_tls_info", return_value=None):
            results = checker.run()
        for r in results:
            assert r.engine == "blackbox"
