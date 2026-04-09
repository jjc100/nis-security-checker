"""
블랙박스 검사 - 로그인 잠금 검사기 단위 테스트
"""

from unittest.mock import patch

import pytest

from src.engines.blackbox.login_tester import LoginTester
from src.models import TestStatus


@pytest.fixture
def tester():
    return LoginTester(
        host="192.168.1.100",
        port=443,
        username="admin",
        max_attempts=5,
    )


class TestLockout:
    """로그인 잠금 검사 테스트"""

    def test_pass_when_locked_after_attempts(self, tester):
        """5회 실패 후 잠금(423) 응답 시 PASS여야 한다."""
        side_effects = [(401, "Unauthorized")] * 5 + [(423, "Account locked")]
        with patch.object(tester, "_attempt_login", side_effect=side_effects):
            result = tester.check_lockout()
        assert result.status == TestStatus.PASS

    def test_fail_when_not_locked(self, tester):
        """5회 실패 후에도 잠금이 없으면 FAIL이어야 한다."""
        side_effects = [(401, "Unauthorized")] * 6
        with patch.object(tester, "_attempt_login", side_effect=side_effects):
            result = tester.check_lockout()
        assert result.status == TestStatus.FAIL

    def test_pass_when_too_many_requests(self, tester):
        """429(Too Many Requests) 응답 시 PASS여야 한다."""
        side_effects = [(401, "Unauthorized")] * 5 + [(429, "Too many requests")]
        with patch.object(tester, "_attempt_login", side_effect=side_effects):
            result = tester.check_lockout()
        assert result.status == TestStatus.PASS

    def test_result_id(self, tester):
        """결과 ID가 AUTH-003이어야 한다."""
        side_effects = [(401, "Unauthorized")] * 6
        with patch.object(tester, "_attempt_login", side_effect=side_effects):
            result = tester.check_lockout()
        assert result.id == "AUTH-003"
        assert result.engine == "blackbox"


class TestSameErrorMessage:
    """동일 오류 메시지 검사 테스트"""

    def test_result_id(self, tester):
        """결과 ID가 AUTH-005이어야 한다."""
        with patch.object(tester, "_attempt_login", return_value=(401, "Login failed")):
            result = tester.check_same_error_message()
        assert result.id == "AUTH-005"
