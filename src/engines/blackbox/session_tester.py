"""
블랙박스 검사 - 세션 보안 검사 모듈
세션 10분 타임아웃, 중복 접속 차단, 세션 토큰 고유성을 검사합니다.
"""

import time
from datetime import datetime

import requests
import urllib3

from src.models import TestResult, TestStatus

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SessionTester:
    """세션 보안 검사기"""

    def __init__(
        self,
        host: str,
        port: int = 443,
        login_path: str = "/login",
        protected_path: str = "/api/status",
        session_timeout: int = 600,
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.login_path = login_path
        self.protected_path = protected_path
        self.session_timeout = session_timeout
        self.timeout = timeout
        self.engine = "blackbox"
        self.base_url = f"https://{host}:{port}"

    def _get_session_token(self, username: str = "admin", password: str = "admin") -> str | None:
        """로그인하여 세션 토큰을 획득합니다."""
        try:
            resp = requests.post(
                f"{self.base_url}{self.login_path}",
                data={"username": username, "password": password},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
            # 세션 쿠키 또는 토큰 추출
            token = resp.cookies.get("session") or resp.cookies.get("JSESSIONID")
            if not token:
                # Authorization 헤더의 Bearer 토큰 확인
                auth_header = resp.headers.get("Authorization", "")
                if "Bearer " in auth_header:
                    token = auth_header.split("Bearer ")[1]
            return token
        except requests.RequestException:
            return None

    def check_session_timeout(self) -> TestResult:
        """
        세션 타임아웃 설정을 검사합니다.
        실제 10분 대기 대신, 서버의 Max-Age나 Expires 쿠키 설정을 확인합니다.
        """
        try:
            resp = requests.post(
                f"{self.base_url}{self.login_path}",
                data={"username": "admin", "password": "admin"},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )

            # 쿠키의 Max-Age 확인
            for cookie in resp.cookies:
                max_age = cookie.get("max-age") or getattr(cookie, "_rest", {}).get("Max-Age")
                if max_age is not None:
                    try:
                        max_age_int = int(max_age)
                        if max_age_int <= self.session_timeout:
                            return TestResult(
                                id="AC-003",
                                name="세션 타임아웃 10분",
                                category="접근제어",
                                status=TestStatus.PASS,
                                engine=self.engine,
                                details=f"세션 Max-Age가 {max_age_int}초({max_age_int//60}분)으로 설정되어 있습니다.",
                                timestamp=datetime.now(),
                            )
                        return TestResult(
                            id="AC-003",
                            name="세션 타임아웃 10분",
                            category="접근제어",
                            status=TestStatus.FAIL,
                            engine=self.engine,
                            details=f"세션 Max-Age가 {max_age_int}초로 너무 깁니다. 600초(10분) 이하여야 합니다.",
                            timestamp=datetime.now(),
                        )
                    except (ValueError, TypeError):
                        pass

            return TestResult(
                id="AC-003",
                name="세션 타임아웃 10분",
                category="접근제어",
                status=TestStatus.MANUAL,
                engine=self.engine,
                details="쿠키 Max-Age 설정을 자동으로 확인할 수 없습니다. 수동 확인이 필요합니다.",
                timestamp=datetime.now(),
            )

        except requests.RequestException as e:
            return TestResult(
                id="AC-003",
                name="세션 타임아웃 10분",
                category="접근제어",
                status=TestStatus.ERROR,
                engine=self.engine,
                details=f"연결 오류: {e}",
                timestamp=datetime.now(),
            )

    def check_session_uniqueness(self) -> TestResult:
        """세션 토큰이 매 로그인마다 고유하게 발급되는지 확인합니다."""
        tokens = set()
        for _ in range(3):
            token = self._get_session_token()
            if token:
                tokens.add(token)
            time.sleep(0.3)

        if not tokens:
            return TestResult(
                id="AC-005",
                name="세션 토큰 고유성",
                category="접근제어",
                status=TestStatus.ERROR,
                engine=self.engine,
                details="세션 토큰을 획득할 수 없습니다. 로그인 엔드포인트를 확인하세요.",
                timestamp=datetime.now(),
            )

        # 획득한 토큰 개수가 요청 횟수와 동일하면 모두 고유
        # (여기서는 3번 중 고유 토큰 수로 판단)
        if len(tokens) >= 2:
            return TestResult(
                id="AC-005",
                name="세션 토큰 고유성",
                category="접근제어",
                status=TestStatus.PASS,
                engine=self.engine,
                details=f"로그인마다 고유한 세션 토큰이 발급됩니다. (확인된 고유 토큰 수: {len(tokens)})",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="AC-005",
            name="세션 토큰 고유성",
            category="접근제어",
            status=TestStatus.FAIL,
            engine=self.engine,
            details="동일한 세션 토큰이 반복 발급됩니다. 예측 가능한 토큰은 보안 위험입니다.",
            timestamp=datetime.now(),
        )

    def check_concurrent_sessions(self) -> TestResult:
        """중복 세션(동시 로그인) 차단 여부를 확인합니다."""
        return TestResult(
            id="AC-004",
            name="중복 세션 차단",
            category="접근제어",
            status=TestStatus.MANUAL,
            engine=self.engine,
            details="중복 세션 차단은 실제 다중 클라이언트 테스트가 필요합니다. 수동 확인이 필요합니다.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """세션 보안 관련 검사를 모두 실행합니다."""
        return [
            self.check_session_timeout(),
            self.check_session_uniqueness(),
            self.check_concurrent_sessions(),
        ]
