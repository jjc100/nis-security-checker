"""
블랙박스 검사 - RTSP/ONVIF 프로토콜 인증 검사 모듈
RTSP DESCRIBE 요청 인증 확인, ONVIF SOAP 인증 확인, Digest 알고리즘 강도를 검사합니다.
"""

import re
import socket
from datetime import datetime

from src.models import TestResult, TestStatus

# 취약한 Digest 알고리즘
WEAK_DIGEST_ALGORITHMS = {"MD5", "MD5-SESS"}

# ONVIF 기기 서비스 경로
ONVIF_DEVICE_PATH = "/onvif/device_service"


class ProtocolAuthChecker:
    """RTSP/ONVIF 프로토콜 인증 검사기"""

    def __init__(
        self,
        host: str,
        rtsp_port: int = 554,
        http_port: int = 80,
        has_rtsp: bool = True,
        has_onvif: bool = True,
    ) -> None:
        self.host = host
        self.rtsp_port = rtsp_port
        self.http_port = http_port
        self.has_rtsp = has_rtsp
        self.has_onvif = has_onvif
        self.engine = "blackbox"

    def _send_rtsp_describe(self) -> str:
        """RTSP DESCRIBE 요청을 전송하고 응답을 반환합니다."""
        rtsp_request = (
            f"DESCRIBE rtsp://{self.host}:{self.rtsp_port}/ RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: NIS-Security-Checker/1.0\r\n"
            f"\r\n"
        )
        try:
            with socket.create_connection((self.host, self.rtsp_port), timeout=10) as sock:
                sock.sendall(rtsp_request.encode())
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        break
            return response.decode(errors="replace")
        except OSError as e:
            return f"ERROR: {e}"

    def check_rtsp_auth(self) -> TestResult:
        """RTSP 스트리밍에 인증이 필요한지 확인합니다."""
        if not self.has_rtsp:
            return TestResult(
                id="AUTH-008",
                name="RTSP 인증 필수 적용",
                category="인증",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="RTSP 기능이 비활성화되어 있어 검사를 건너뜁니다.",
                timestamp=datetime.now(),
            )

        response = self._send_rtsp_describe()

        if response.startswith("ERROR:"):
            return TestResult(
                id="AUTH-008",
                name="RTSP 인증 필수 적용",
                category="인증",
                status=TestStatus.ERROR,
                engine=self.engine,
                details=f"RTSP 연결 실패: {response}",
                timestamp=datetime.now(),
            )

        # 401 Unauthorized 확인
        if "401" in response[:20]:
            return TestResult(
                id="AUTH-008",
                name="RTSP 인증 필수 적용",
                category="인증",
                status=TestStatus.PASS,
                engine=self.engine,
                details="RTSP DESCRIBE 요청에 401 인증 요구가 반환됩니다.",
                timestamp=datetime.now(),
            )

        # 200 OK 또는 다른 응답 → 인증 없이 접근 가능
        return TestResult(
            id="AUTH-008",
            name="RTSP 인증 필수 적용",
            category="인증",
            status=TestStatus.FAIL,
            engine=self.engine,
            details=f"RTSP 인증 없이 접근 가능합니다. 응답 첫 줄: {response.splitlines()[0] if response else '없음'}",
            timestamp=datetime.now(),
        )

    def check_rtsp_digest_strength(self) -> TestResult:
        """RTSP 401 응답의 Digest 알고리즘 강도를 확인합니다."""
        if not self.has_rtsp:
            return TestResult(
                id="NET-002",
                name="RTSP Digest 인증 강도",
                category="네트워크보안",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="RTSP 기능이 비활성화되어 있어 검사를 건너뜁니다.",
                timestamp=datetime.now(),
            )

        response = self._send_rtsp_describe()

        if response.startswith("ERROR:") or "401" not in response[:20]:
            return TestResult(
                id="NET-002",
                name="RTSP Digest 인증 강도",
                category="네트워크보안",
                status=TestStatus.ERROR,
                engine=self.engine,
                details="RTSP 401 응답을 받지 못해 Digest 알고리즘을 확인할 수 없습니다.",
                timestamp=datetime.now(),
            )

        # WWW-Authenticate 헤더에서 algorithm 파라미터 추출
        match = re.search(r'algorithm\s*=\s*"?([^",\s]+)"?', response, re.IGNORECASE)
        algorithm = match.group(1).upper() if match else "MD5"  # 기본값은 MD5

        if algorithm in WEAK_DIGEST_ALGORITHMS:
            return TestResult(
                id="NET-002",
                name="RTSP Digest 인증 강도",
                category="네트워크보안",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"취약한 Digest 알고리즘 사용: {algorithm}. SHA-256 이상을 사용해야 합니다.",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="NET-002",
            name="RTSP Digest 인증 강도",
            category="네트워크보안",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"강력한 Digest 알고리즘 사용: {algorithm}",
            timestamp=datetime.now(),
        )

    def check_onvif_auth(self) -> TestResult:
        """ONVIF 인터페이스에 인증이 필요한지 확인합니다."""
        if not self.has_onvif:
            return TestResult(
                id="AUTH-007",
                name="ONVIF 인증 필수 적용",
                category="인증",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="ONVIF 기능이 비활성화되어 있어 검사를 건너뜁니다.",
                timestamp=datetime.now(),
            )

        # 인증 없는 ONVIF GetDeviceInformation SOAP 요청
        soap_body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            '<s:Body>'
            '<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
            '</s:Body>'
            '</s:Envelope>'
        )
        headers = (
            f"POST {ONVIF_DEVICE_PATH} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.http_port}\r\n"
            f"Content-Type: application/soap+xml; charset=utf-8\r\n"
            f"Content-Length: {len(soap_body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        try:
            with socket.create_connection((self.host, self.http_port), timeout=10) as sock:
                sock.sendall((headers + soap_body).encode())
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            resp_str = response.decode(errors="replace")
        except OSError as e:
            return TestResult(
                id="AUTH-007",
                name="ONVIF 인증 필수 적용",
                category="인증",
                status=TestStatus.ERROR,
                engine=self.engine,
                details=f"ONVIF 연결 실패: {e}",
                timestamp=datetime.now(),
            )

        # 401 또는 SOAP Fault (인증 오류) 확인
        if "401" in resp_str[:50] or "NotAuthorized" in resp_str or "Sender" in resp_str:
            return TestResult(
                id="AUTH-007",
                name="ONVIF 인증 필수 적용",
                category="인증",
                status=TestStatus.PASS,
                engine=self.engine,
                details="ONVIF 인터페이스에서 인증 없이 접근을 거부합니다.",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="AUTH-007",
            name="ONVIF 인증 필수 적용",
            category="인증",
            status=TestStatus.FAIL,
            engine=self.engine,
            details="ONVIF 인터페이스에 인증 없이 접근이 가능합니다.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """프로토콜 인증 관련 검사를 모두 실행합니다."""
        return [
            self.check_rtsp_auth(),
            self.check_rtsp_digest_strength(),
            self.check_onvif_auth(),
        ]
