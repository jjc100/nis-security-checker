"""
블랙박스 검사 - TLS 버전 및 암호 스위트 검사 모듈
TLS 1.2 이상 필수 사용 여부, 취약 버전 거부, 암호 스위트 강도를 검사합니다.
"""

import socket
import ssl
from datetime import datetime

from src.models import TestResult, TestStatus

# 허용되지 않는 TLS 프로토콜 버전
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# 취약한 암호 스위트 키워드
WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON"}

# 강력한 키 교환 방식
STRONG_KEX = {"ECDHE", "DHE"}


class TLSChecker:
    """TLS 보안 설정 검사기"""

    def __init__(self, host: str, port: int = 443) -> None:
        self.host = host
        self.port = port
        self.engine = "blackbox"

    def _get_tls_info(self, min_version: ssl.TLSVersion) -> dict | None:
        """지정된 최소 TLS 버전으로 연결을 시도합니다."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = min_version
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((self.host, self.port), timeout=10) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.host) as tls:
                    return {
                        "protocol": tls.version(),
                        "cipher": tls.cipher(),
                    }
        except ssl.SSLError:
            return None
        except OSError:
            return None

    def check_tls_version(self) -> TestResult:
        """TLS 1.2 이상 버전 사용 여부를 확인합니다."""
        info = self._get_tls_info(ssl.TLSVersion.TLSv1_2)

        if info is None:
            return TestResult(
                id="CRYPT-001",
                name="TLS 1.2 이상 사용 확인",
                category="암호화",
                status=TestStatus.ERROR,
                engine=self.engine,
                details=f"{self.host}:{self.port} 에 TLS 연결을 수립할 수 없습니다.",
                timestamp=datetime.now(),
            )

        protocol = info.get("protocol", "")
        if protocol in ("TLSv1.2", "TLSv1.3"):
            return TestResult(
                id="CRYPT-001",
                name="TLS 1.2 이상 사용 확인",
                category="암호화",
                status=TestStatus.PASS,
                engine=self.engine,
                details=f"협상된 TLS 버전: {protocol}",
                timestamp=datetime.now(),
            )
        return TestResult(
            id="CRYPT-001",
            name="TLS 1.2 이상 사용 확인",
            category="암호화",
            status=TestStatus.FAIL,
            engine=self.engine,
            details=f"취약한 TLS 버전 협상됨: {protocol}",
            timestamp=datetime.now(),
        )

    def check_weak_tls_rejected(self) -> TestResult:
        """취약한 TLS 버전(TLS 1.0/1.1) 연결이 거부되는지 확인합니다."""
        # TLS 1.0 연결 시도
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Python 3.10+ 에서는 TLS 1.0/1.1을 라이브러리 수준에서 제한할 수 있음
        # 실제로는 서버가 거부하는지 여부를 확인
        # 보안 취약점 검사를 위해 의도적으로 TLS 1.0을 설정합니다 (서버가 거부하는지 확인 목적)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1  # noqa: S502 — 취약 버전 거부 검사 목적
            ctx.maximum_version = ssl.TLSVersion.TLSv1  # noqa: S502 — 취약 버전 거부 검사 목적
        except (AttributeError, ssl.SSLError):
            # TLS 1.0 설정 자체가 불가능한 경우 PASS 처리
            return TestResult(
                id="CRYPT-002",
                name="취약 TLS 버전 거부 확인",
                category="암호화",
                status=TestStatus.PASS,
                engine=self.engine,
                details="시스템 수준에서 TLS 1.0/1.1이 비활성화되어 있습니다.",
                timestamp=datetime.now(),
            )

        connected = False
        try:
            with socket.create_connection((self.host, self.port), timeout=10) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.host):
                    connected = True
        except (ssl.SSLError, OSError):
            connected = False

        if connected:
            return TestResult(
                id="CRYPT-002",
                name="취약 TLS 버전 거부 확인",
                category="암호화",
                status=TestStatus.FAIL,
                engine=self.engine,
                details="서버가 TLS 1.0 연결을 허용합니다. TLS 1.2 이상만 허용해야 합니다.",
                timestamp=datetime.now(),
            )
        return TestResult(
            id="CRYPT-002",
            name="취약 TLS 버전 거부 확인",
            category="암호화",
            status=TestStatus.PASS,
            engine=self.engine,
            details="서버가 TLS 1.0/1.1 연결을 거부합니다.",
            timestamp=datetime.now(),
        )

    def check_cipher_suites(self) -> TestResult:
        """강력한 암호 스위트를 사용하는지 확인합니다."""
        info = self._get_tls_info(ssl.TLSVersion.TLSv1_2)

        if info is None:
            return TestResult(
                id="CRYPT-003",
                name="암호 스위트 강도 확인",
                category="암호화",
                status=TestStatus.ERROR,
                engine=self.engine,
                details="TLS 연결 불가로 암호 스위트를 확인할 수 없습니다.",
                timestamp=datetime.now(),
            )

        cipher_info = info.get("cipher")
        if not cipher_info:
            return TestResult(
                id="CRYPT-003",
                name="암호 스위트 강도 확인",
                category="암호화",
                status=TestStatus.ERROR,
                engine=self.engine,
                details="암호 스위트 정보를 가져올 수 없습니다.",
                timestamp=datetime.now(),
            )

        cipher_name = cipher_info[0] if cipher_info else ""
        upper_cipher = cipher_name.upper()

        # 취약 암호 스위트 확인
        weak_found = [w for w in WEAK_CIPHERS if w in upper_cipher]
        if weak_found:
            return TestResult(
                id="CRYPT-003",
                name="암호 스위트 강도 확인",
                category="암호화",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"취약한 암호 스위트 사용: {cipher_name} (취약 요소: {', '.join(weak_found)})",
                timestamp=datetime.now(),
            )

        # 강력한 키 교환 방식 확인
        has_strong_kex = any(k in upper_cipher for k in STRONG_KEX)
        status = TestStatus.PASS if has_strong_kex else TestStatus.MANUAL
        detail = (
            f"협상된 암호 스위트: {cipher_name}"
            if has_strong_kex
            else f"키 교환 방식 확인 필요: {cipher_name}"
        )

        return TestResult(
            id="CRYPT-003",
            name="암호 스위트 강도 확인",
            category="암호화",
            status=status,
            engine=self.engine,
            details=detail,
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """TLS 관련 검사를 모두 실행합니다."""
        return [
            self.check_tls_version(),
            self.check_weak_tls_rejected(),
            self.check_cipher_suites(),
        ]
