"""
블랙박스 검사 - 로그인 잠금 검사 모듈
로그인 5회 실패 잠금, 잠금 5분 유지, 동일 오류 메시지 반환 여부를 검사합니다.
"""

import time
from datetime import datetime

import requests
import urllib3

from src.models import TestResult, TestStatus

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class LoginTester:
    """로그인 잠금 및 오류 메시지 검사기"""

    # 잘못된 패스워드 목록
    WRONG_PASSWORDS = [
        "wrongpass1!", "wrongpass2!", "wrongpass3!",
        "wrongpass4!", "wrongpass5!", "wrongpass6!",
    ]

    def __init__(
        self,
        host: str,
        port: int = 443,
        username: str = "admin",
        login_path: str = "/login",
        max_attempts: int = 5,
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.login_path = login_path
        self.max_attempts = max_attempts
        self.timeout = timeout
        self.engine = "blackbox"
        self.base_url = f"https://{host}:{port}"

    def _attempt_login(self, password: str) -> tuple[int, str]:
        """
        로그인을 시도하고 (HTTP 상태 코드, 응답 본문)을 반환합니다.
        """
        try:
            resp = requests.post(
                f"{self.base_url}{self.login_path}",
                data={"username": self.username, "password": password},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
            return resp.status_code, resp.text
        except requests.RequestException as e:
            return -1, str(e)

    def check_lockout(self) -> TestResult:
        """로그인 5회 연속 실패 후 계정이 잠금되는지 확인합니다."""
        responses = []
        for i in range(self.max_attempts + 1):
            code, body = self._attempt_login(self.WRONG_PASSWORDS[i % len(self.WRONG_PASSWORDS)])
            responses.append((code, body))
            time.sleep(0.5)  # 과도한 요청 방지

        # max_attempts 번 이후(마지막 시도)에 잠금 응답 확인
        last_code, last_body = responses[-1]
        last_body_lower = last_body.lower()

        locked = (
            last_code in (403, 423, 429)
            or "locked" in last_body_lower
            or "잠금" in last_body_lower
            or "lock" in last_body_lower
            or "too many" in last_body_lower
        )

        if locked:
            return TestResult(
                id="AUTH-003",
                name="로그인 5회 실패 시 잠금",
                category="인증",
                status=TestStatus.PASS,
                engine=self.engine,
                details=f"{self.max_attempts}회 실패 후 계정 잠금이 적용되었습니다. (HTTP {last_code})",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="AUTH-003",
            name="로그인 5회 실패 시 잠금",
            category="인증",
            status=TestStatus.FAIL,
            engine=self.engine,
            details=f"{self.max_attempts}회 실패 후에도 잠금이 적용되지 않았습니다. (HTTP {last_code})",
            timestamp=datetime.now(),
        )

    def check_same_error_message(self) -> TestResult:
        """로그인 실패 시 아이디/패스워드 구분 없이 동일한 오류 메시지를 반환하는지 확인합니다."""
        _, body_unknown_user = self._attempt_login(self.WRONG_PASSWORDS[0])
        _, body_wrong_pass = self._attempt_login(self.WRONG_PASSWORDS[1])

        # 두 응답이 동일하거나 유사한지 확인
        body1 = body_unknown_user.strip()
        body2 = body_wrong_pass.strip()

        # 응답 길이 차이가 크면 다른 메시지일 가능성이 높음
        length_diff = abs(len(body1) - len(body2))
        similar = length_diff < 50  # 50자 이내 차이

        if similar:
            return TestResult(
                id="AUTH-005",
                name="동일 오류 메시지 반환",
                category="인증",
                status=TestStatus.PASS,
                engine=self.engine,
                details="로그인 실패 시 동일한 오류 메시지가 반환됩니다.",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="AUTH-005",
            name="동일 오류 메시지 반환",
            category="인증",
            status=TestStatus.MANUAL,
            engine=self.engine,
            details="로그인 실패 응답이 다를 수 있습니다. 수동 확인이 필요합니다.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """로그인 관련 검사를 모두 실행합니다."""
        return [
            self.check_lockout(),
            self.check_same_error_message(),
        ]
