"""
그레이박스 검사 - 하드코딩 암호키 탐지 모듈
strings 명령어와 엔트로피 분석으로 바이너리 내 하드코딩된 키를 탐지합니다.
"""

import base64
import re
import subprocess
from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus
from src.utils.crypto import calculate_entropy

# 하드코딩 키 패턴 (Base64, 16진수 키, PEM 헤더 등)
KEY_PATTERNS = [
    re.compile(r'-----BEGIN (RSA |EC |DSA |PRIVATE |OPENSSH )?PRIVATE KEY-----'),
    re.compile(r'-----BEGIN CERTIFICATE-----'),
    re.compile(r'AES_KEY\s*[=:]\s*["\']([A-Za-z0-9+/=]{24,})["\']', re.IGNORECASE),
    re.compile(r'SECRET_KEY\s*[=:]\s*["\']([^"\']{16,})["\']', re.IGNORECASE),
    re.compile(r'ENCRYPTION_KEY\s*[=:]\s*["\']([^"\']{16,})["\']', re.IGNORECASE),
    re.compile(r'PRIVATE_KEY\s*[=:]\s*["\']([^"\']{16,})["\']', re.IGNORECASE),
]

# 분석할 디렉토리
SCAN_DIRS = ["/opt", "/usr/local/bin", "/usr/local/lib"]

# 엔트로피 임계값 (높은 값 = 랜덤 데이터 가능성)
ENTROPY_THRESHOLD = 7.0

# 최소 Base64 문자열 길이 (24자 이상 = 18바이트)
MIN_B64_LENGTH = 24


class HardcodedKeyScanner:
    """하드코딩 암호키 탐지기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"

    def _get_strings(self, filepath: str, min_len: int = 8) -> list[str]:
        """바이너리에서 가독 문자열을 추출합니다."""
        try:
            result = subprocess.run(  # noqa: S603
                ["strings", "-n", str(min_len), filepath],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout.splitlines()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return []

    def _is_high_entropy_b64(self, s: str) -> bool:
        """
        Base64처럼 보이고 엔트로피가 높은 문자열인지 확인합니다.
        """
        b64_pattern = re.compile(r'^[A-Za-z0-9+/]{' + str(MIN_B64_LENGTH) + r',}={0,2}$')
        if not b64_pattern.match(s):
            return False
        try:
            decoded = base64.b64decode(s + "==")
            return calculate_entropy(decoded) >= ENTROPY_THRESHOLD
        except Exception:
            return False

    def _find_binaries(self, max_count: int = 20) -> list[Path]:
        """분석할 실행 파일 목록을 반환합니다."""
        binaries = []
        for dir_str in SCAN_DIRS:
            dir_path = Path(dir_str)
            if not dir_path.exists():
                continue
            for fpath in dir_path.rglob("*"):
                if fpath.is_file() and not fpath.suffix:
                    binaries.append(fpath)
                    if len(binaries) >= max_count:
                        return binaries
        return binaries

    def check_hardcoded_keys(self) -> TestResult:
        """바이너리에서 하드코딩된 암호키를 탐지합니다."""
        binaries = self._find_binaries()

        if not binaries:
            return TestResult(
                id="CRYPT-008",
                name="하드코딩 암호키 미존재",
                category="암호화",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="분석할 바이너리를 찾을 수 없습니다.",
                timestamp=datetime.now(),
            )

        found_keys = []

        for binary in binaries:
            strings = self._get_strings(str(binary))
            for s in strings:
                # 패턴 매칭
                for pattern in KEY_PATTERNS:
                    if pattern.search(s):
                        found_keys.append(f"{binary.name}: 키 패턴 탐지")
                        break
                # 고엔트로피 Base64 탐지
                if self._is_high_entropy_b64(s):
                    found_keys.append(f"{binary.name}: 고엔트로피 문자열 ({s[:20]}...)")

        if found_keys:
            return TestResult(
                id="CRYPT-008",
                name="하드코딩 암호키 미존재",
                category="암호화",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"하드코딩 키 의심 항목: {'; '.join(found_keys[:5])}",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="CRYPT-008",
            name="하드코딩 암호키 미존재",
            category="암호화",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"{len(binaries)}개 바이너리에서 하드코딩 키 미탐지.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """하드코딩 키 관련 검사를 모두 실행합니다."""
        return [self.check_hardcoded_keys()]
