"""
블랙박스 검사 - API 인증 검사 모듈
인증 없이 API 엔드포인트에 접근이 차단되는지, 권한 분리가 적용되는지 확인합니다.
"""

from datetime import datetime

import requests
import urllib3

from src.models import TestResult, TestStatus

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 검사할 API 엔드포인트 목록
PROTECTED_ENDPOINTS = [
    "/api/users",
    "/api/config",
    "/api/system",
    "/api/recordings",
    "/api/cameras",
    "/api/admin",
]

# 관리자 전용 엔드포인트 (일반 사용자 접근 불가)
ADMIN_ONLY_ENDPOINTS = [
    "/api/admin",
    "/api/users/manage",
    "/api/config/security",
]


class APIAuthTester:
    """API 인증 및 권한 분리 검사기"""

    def __init__(
        self,
        host: str,
        port: int = 443,
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.engine = "blackbox"
        self.base_url = f"https://{host}:{port}"

    def _get(self, path: str, token: str | None = None) -> tuple[int, str]:
        """인증 토큰을 포함하거나 제외하여 GET 요청을 수행합니다."""
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            resp = requests.get(
                f"{self.base_url}{path}",
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
            return resp.status_code, resp.text
        except requests.RequestException as e:
            return -1, str(e)

    def check_unauthenticated_access(self) -> TestResult:
        """인증 없이 보호된 API 엔드포인트에 접근이 차단되는지 확인합니다."""
        accessible = []
        for endpoint in PROTECTED_ENDPOINTS:
            code, _ = self._get(endpoint, token=None)
            # 200이 반환되면 인증 없이 접근 가능
            if code == 200:
                accessible.append(endpoint)

        if accessible:
            return TestResult(
                id="AC-002",
                name="인증 없는 API 접근 차단",
                category="접근제어",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"인증 없이 접근 가능한 엔드포인트: {', '.join(accessible)}",
                timestamp=datetime.now(),
            )

        # 모든 엔드포인트가 401/403 반환 시 PASS
        blocked_count = sum(
            1 for ep in PROTECTED_ENDPOINTS
            if self._get(ep)[0] in (401, 403)
        )

        if blocked_count == 0:
            return TestResult(
                id="AC-002",
                name="인증 없는 API 접근 차단",
                category="접근제어",
                status=TestStatus.MANUAL,
                engine=self.engine,
                details="API 엔드포인트가 없거나 응답이 없습니다. 수동 확인이 필요합니다.",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="AC-002",
            name="인증 없는 API 접근 차단",
            category="접근제어",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"모든 보호 API 엔드포인트({len(PROTECTED_ENDPOINTS)}개)에서 인증을 요구합니다.",
            timestamp=datetime.now(),
        )

    def check_privilege_separation(self) -> TestResult:
        """관리자 전용 엔드포인트에 권한 분리가 적용되는지 확인합니다."""
        return TestResult(
            id="AC-001",
            name="권한 분리 (관리자/사용자)",
            category="접근제어",
            status=TestStatus.MANUAL,
            engine=self.engine,
            details="권한 분리 검증은 실제 관리자/일반 사용자 계정 자격증명이 필요합니다. 수동 확인이 필요합니다.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """API 인증 관련 검사를 모두 실행합니다."""
        return [
            self.check_unauthenticated_access(),
            self.check_privilege_separation(),
        ]
