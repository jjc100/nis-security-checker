"""
블랙박스 검사 - 기본 계정 검사 모듈
기본 계정(admin/admin 등)으로 로그인 가능 여부와 유추 가능한 계정명을 탐지합니다.
"""

from datetime import datetime

import requests
import urllib3

from src.models import TestResult, TestStatus

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 유추 가능한 계정명 목록
GUESSABLE_USERNAMES = {
    "admin", "administrator", "root", "user", "guest",
    "operator", "manager", "test", "demo", "support",
    "service", "camera", "nvr", "dvr", "system",
}


class DefaultCredChecker:
    """기본 계정 및 유추 가능 계정명 검사기"""

    def __init__(
        self,
        host: str,
        port: int = 443,
        login_path: str = "/login",
        default_credentials: list[dict] | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.login_path = login_path
        self.default_credentials = default_credentials or []
        self.timeout = timeout
        self.engine = "blackbox"
        self.base_url = f"https://{host}:{port}"

    def _attempt_login(self, username: str, password: str) -> bool:
        """
        로그인을 시도하고 성공 여부를 반환합니다.

        Returns:
            로그인 성공 여부
        """
        try:
            resp = requests.post(
                f"{self.base_url}{self.login_path}",
                data={"username": username, "password": password},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
            # 200 OK이거나 리다이렉트(302)이면 로그인 성공으로 간주
            return resp.status_code in (200, 302)
        except requests.RequestException:
            return False

    def check_default_credentials(self) -> TestResult:
        """기본 계정으로 로그인이 불가능한지 확인합니다."""
        if not self.default_credentials:
            return TestResult(
                id="AUTH-001",
                name="기본 계정 변경 강제",
                category="인증",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="기본 계정 목록이 설정되지 않아 검사를 건너뜁니다.",
                timestamp=datetime.now(),
            )

        successful_logins = []
        for cred in self.default_credentials:
            username = cred.get("username", "")
            password = cred.get("password", "")
            if self._attempt_login(username, password):
                successful_logins.append(f"{username}/{password}")

        if successful_logins:
            return TestResult(
                id="AUTH-001",
                name="기본 계정 변경 강제",
                category="인증",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"기본 계정으로 로그인 성공: {', '.join(successful_logins)}",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="AUTH-001",
            name="기본 계정 변경 강제",
            category="인증",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"{len(self.default_credentials)}개 기본 계정 모두 로그인 불가 확인.",
            timestamp=datetime.now(),
        )

    def check_guessable_usernames(self) -> TestResult:
        """유추 가능한 계정명이 존재하는지 확인합니다."""
        return TestResult(
            id="AUTH-002",
            name="유추 가능 계정명 금지",
            category="인증",
            status=TestStatus.MANUAL,
            engine=self.engine,
            details=(
                f"다음 유추 가능 계정명의 존재 여부를 수동으로 확인하세요: "
                f"{', '.join(sorted(GUESSABLE_USERNAMES))}"
            ),
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """기본 계정 관련 검사를 모두 실행합니다."""
        return [
            self.check_default_credentials(),
            self.check_guessable_usernames(),
        ]
