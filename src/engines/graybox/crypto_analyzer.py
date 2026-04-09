"""
그레이박스 검사 - 암호화 알고리즘 분석 모듈
바이너리에서 암호 알고리즘을 탐지하고 금지 알고리즘 사용 여부를 확인합니다.
"""

import subprocess
from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus
from src.utils.crypto import is_weak_algorithm

# 분석할 바이너리/라이브러리 경로
BINARY_PATHS = [
    "/usr/lib",
    "/usr/local/lib",
    "/opt",
    "/usr/sbin",
    "/usr/bin",
]

# 금지 알고리즘 심볼 패턴
FORBIDDEN_SYMBOLS = [
    "DES_ecb_encrypt", "DES_cbc_encrypt",           # DES
    "RC4_set_key", "RC4",                            # RC4
    "MD5_Init", "MD5_Update", "MD5_Final",          # MD5
    "EVP_des_", "EVP_rc4",                           # OpenSSL 금지 알고리즘
]


class CryptoAnalyzer:
    """암호화 알고리즘 분석기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"

    def _get_strings(self, filepath: str, min_length: int = 6) -> list[str]:
        """바이너리 파일에서 문자열을 추출합니다."""
        try:
            result = subprocess.run(  # noqa: S603
                ["strings", "-n", str(min_length), filepath],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout.splitlines()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return []

    def _find_binaries(self, max_count: int = 20) -> list[Path]:
        """분석할 바이너리 파일 목록을 반환합니다."""
        binaries = []
        for path_str in BINARY_PATHS:
            path = Path(path_str)
            if not path.exists():
                continue
            for fpath in path.rglob("*.so*"):
                if fpath.is_file():
                    binaries.append(fpath)
                    if len(binaries) >= max_count:
                        return binaries
        return binaries

    def check_forbidden_algorithms(self) -> TestResult:
        """바이너리에서 금지 암호 알고리즘 사용 여부를 확인합니다."""
        binaries = self._find_binaries()

        if not binaries:
            return TestResult(
                id="CRYPT-004",
                name="금지 암호 알고리즘 미사용",
                category="암호화",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="분석할 바이너리를 찾을 수 없습니다. 접근 권한이 필요할 수 있습니다.",
                timestamp=datetime.now(),
            )

        found_weak = {}
        for binary in binaries:
            strings = self._get_strings(str(binary))
            all_text = " ".join(strings)
            weak_algos = is_weak_algorithm(all_text)
            if weak_algos:
                found_weak[str(binary.name)] = weak_algos

        if found_weak:
            details = "; ".join(
                f"{name}: {', '.join(algos)}"
                for name, algos in list(found_weak.items())[:3]
            )
            return TestResult(
                id="CRYPT-004",
                name="금지 암호 알고리즘 미사용",
                category="암호화",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"금지 알고리즘 탐지: {details}",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="CRYPT-004",
            name="금지 암호 알고리즘 미사용",
            category="암호화",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"{len(binaries)}개 바이너리 분석 완료. 금지 알고리즘 미탐지.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """암호화 알고리즘 관련 검사를 모두 실행합니다."""
        return [self.check_forbidden_algorithms()]
