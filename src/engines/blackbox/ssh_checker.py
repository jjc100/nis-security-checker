"""
블랙박스 검사 - SSH 버전 검사 모듈
SSH 배너를 확인하여 SSH-2.0 프로토콜 사용 여부를 검사합니다.
"""

import socket
from datetime import datetime

from src.models import TestResult, TestStatus


class SSHChecker:
    """SSH 프로토콜 버전 검사기"""

    def __init__(self, host: str, port: int = 22, timeout: float = 10.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.engine = "blackbox"

    def _get_ssh_banner(self) -> str | None:
        """SSH 서버 배너를 읽어 반환합니다."""
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                banner = sock.recv(256).decode(errors="replace").strip()
            return banner
        except OSError:
            return None

    def check_ssh_version(self) -> TestResult:
        """SSH 프로토콜 버전이 2.0인지 확인합니다."""
        banner = self._get_ssh_banner()

        if banner is None:
            return TestResult(
                id="SSH-001",
                name="SSH 프로토콜 버전 2 사용",
                category="SSH보안",
                status=TestStatus.ERROR,
                engine=self.engine,
                details=f"{self.host}:{self.port}에 SSH 연결을 할 수 없습니다.",
                timestamp=datetime.now(),
            )

        # SSH 배너 형식: SSH-<프로토콜버전>-<소프트웨어버전>
        if banner.startswith("SSH-2.0"):
            return TestResult(
                id="SSH-001",
                name="SSH 프로토콜 버전 2 사용",
                category="SSH보안",
                status=TestStatus.PASS,
                engine=self.engine,
                details=f"SSH-2.0 프로토콜이 사용됩니다. 배너: {banner}",
                timestamp=datetime.now(),
            )

        if banner.startswith("SSH-1."):
            return TestResult(
                id="SSH-001",
                name="SSH 프로토콜 버전 2 사용",
                category="SSH보안",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"취약한 SSH-1.x 프로토콜이 사용됩니다. 배너: {banner}",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="SSH-001",
            name="SSH 프로토콜 버전 2 사용",
            category="SSH보안",
            status=TestStatus.MANUAL,
            engine=self.engine,
            details=f"SSH 배너를 파싱할 수 없습니다. 수동 확인이 필요합니다. 배너: {banner}",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """SSH 관련 검사를 모두 실행합니다."""
        return [self.check_ssh_version()]
