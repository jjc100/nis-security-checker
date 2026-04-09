"""
블랙박스 검사 - TCP 포트 스캔 모듈
열린 포트를 탐지하고 불필요한 서비스를 식별합니다.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from src.models import TestResult, TestStatus

# 필수 서비스 포트 (정상적으로 열려 있어야 하는 포트)
ALLOWED_PORTS = {443, 554, 8443, 8080}

# 위험 서비스 포트 (열려 있으면 위험)
DANGEROUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    2323: "Telnet(대체)",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

# 스캔할 포트 범위
SCAN_RANGE_LOW = list(range(1, 1025))
SCAN_RANGE_COMMON = [1194, 3389, 5900, 6379, 8080, 8443, 8888, 27017]


class PortScanner:
    """TCP 포트 스캔 검사기"""

    def __init__(
        self,
        host: str,
        timeout: float = 1.0,
        max_workers: int = 50,
    ) -> None:
        self.host = host
        self.timeout = timeout
        self.max_workers = max_workers
        self.engine = "blackbox"

    def _check_port(self, port: int) -> bool:
        """단일 포트의 연결 가능 여부를 반환합니다."""
        try:
            with socket.create_connection((self.host, port), timeout=self.timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def scan_ports(self, ports: list[int]) -> list[int]:
        """
        지정된 포트 목록을 병렬로 스캔합니다.

        Args:
            ports: 스캔할 포트 번호 목록

        Returns:
            열려 있는 포트 번호 목록
        """
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self._check_port, p): p for p in ports}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                if future.result():
                    open_ports.append(port)
        return sorted(open_ports)

    def check_unnecessary_services(self) -> TestResult:
        """불필요한 서비스 포트가 열려 있는지 확인합니다."""
        all_ports = SCAN_RANGE_LOW + SCAN_RANGE_COMMON
        all_ports = list(set(all_ports))

        open_ports = self.scan_ports(all_ports)

        # 위험 포트 탐지
        found_dangerous = {
            p: DANGEROUS_PORTS[p]
            for p in open_ports
            if p in DANGEROUS_PORTS
        }

        if found_dangerous:
            details = "위험 포트 발견: " + ", ".join(
                f"{p}({svc})" for p, svc in found_dangerous.items()
            )
            return TestResult(
                id="AC-006",
                name="불필요 서비스 포트 차단",
                category="접근제어",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=details,
                timestamp=datetime.now(),
            )

        open_str = ", ".join(str(p) for p in open_ports) if open_ports else "없음"
        return TestResult(
            id="AC-006",
            name="불필요 서비스 포트 차단",
            category="접근제어",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"위험 포트 미탐지. 열린 포트: {open_str}",
            timestamp=datetime.now(),
        )

    def check_http_disabled(self) -> TestResult:
        """HTTP(80번 포트, 비암호화) 서비스가 비활성화되어 있는지 확인합니다."""
        http_open = self._check_port(80)

        if http_open:
            # HTTP 리다이렉트 여부 확인
            import urllib.request
            try:
                req = urllib.request.Request(
                    f"http://{self.host}/",
                    headers={"User-Agent": "NIS-Security-Checker/1.0"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
                    final_url = resp.url
                    if final_url.startswith("https://"):
                        return TestResult(
                            id="NET-001",
                            name="불필요한 프로토콜 비활성화",
                            category="네트워크보안",
                            status=TestStatus.PASS,
                            engine=self.engine,
                            details="HTTP(80)가 열려 있으나 HTTPS로 자동 리다이렉트됩니다.",
                            timestamp=datetime.now(),
                        )
            except Exception:
                pass

            return TestResult(
                id="NET-001",
                name="불필요한 프로토콜 비활성화",
                category="네트워크보안",
                status=TestStatus.FAIL,
                engine=self.engine,
                details="HTTP(80번 포트)가 열려 있습니다. 비암호화 HTTP를 비활성화하거나 HTTPS로 리다이렉트해야 합니다.",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="NET-001",
            name="불필요한 프로토콜 비활성화",
            category="네트워크보안",
            status=TestStatus.PASS,
            engine=self.engine,
            details="HTTP(80번 포트)가 비활성화되어 있습니다.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """포트 스캔 관련 검사를 모두 실행합니다."""
        return [
            self.check_unnecessary_services(),
            self.check_http_disabled(),
        ]
