"""
그레이박스 검사 - 패스워드 해시 분석 모듈
패스워드 해시 포맷 식별, 솔트 길이/iteration 횟수 검증을 수행합니다.
"""

import re
from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus
from src.utils.crypto import identify_hash_format, is_strong_hash

# 패스워드 데이터베이스 경로
PASSWORD_DB_PATHS = [
    "/etc/shadow",
    "/etc/passwd",
    "/var/lib/nvr/users.db",
    "/opt/camera/config/users.conf",
]

# 취약한 해시 포맷
WEAK_HASH_FORMATS = {"md5_crypt", "des_crypt", "ntlm"}

# PBKDF2 최소 반복 횟수
MIN_PBKDF2_ITERATIONS = 10000

# 최소 솔트 길이 (바이트)
MIN_SALT_LENGTH = 16


class HashAnalyzer:
    """패스워드 해시 분석기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"

    def _read_password_db(self) -> list[str]:
        """패스워드 데이터베이스 파일에서 해시 문자열을 추출합니다."""
        hashes = []
        for path_str in PASSWORD_DB_PATHS:
            path = Path(path_str)
            if not path.exists():
                continue
            try:
                content = path.read_text(errors="ignore")
                for line in content.splitlines():
                    parts = line.split(":")
                    if len(parts) >= 2:
                        candidate = parts[1].strip()
                        if len(candidate) > 10 and candidate not in ("x", "*", "!"):
                            hashes.append(candidate)
            except OSError:
                continue
        return hashes

    def check_hash_format(self) -> TestResult:
        """패스워드 해시 포맷이 안전한지 확인합니다."""
        hashes = self._read_password_db()

        if not hashes:
            return TestResult(
                id="CRYPT-005",
                name="패스워드 단방향 해시 저장",
                category="암호화",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="패스워드 데이터베이스를 읽을 수 없습니다. 접근 권한이 필요할 수 있습니다.",
                timestamp=datetime.now(),
            )

        weak_hashes = []
        unknown_hashes = []

        for h in hashes:
            fmt = identify_hash_format(h)
            if fmt is None:
                unknown_hashes.append(h[:20] + "...")
            elif not is_strong_hash(fmt):
                weak_hashes.append(fmt)

        if weak_hashes:
            return TestResult(
                id="CRYPT-005",
                name="패스워드 단방향 해시 저장",
                category="암호화",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"취약한 해시 알고리즘 사용: {', '.join(set(weak_hashes))}",
                timestamp=datetime.now(),
            )

        if unknown_hashes:
            return TestResult(
                id="CRYPT-005",
                name="패스워드 단방향 해시 저장",
                category="암호화",
                status=TestStatus.MANUAL,
                engine=self.engine,
                details=f"식별 불가 해시 포맷이 있습니다. 수동 확인이 필요합니다.",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="CRYPT-005",
            name="패스워드 단방향 해시 저장",
            category="암호화",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"{len(hashes)}개 해시 모두 안전한 알고리즘 사용 확인.",
            timestamp=datetime.now(),
        )

    def check_salt_usage(self) -> TestResult:
        """패스워드 해시에 솔트가 적용되어 있는지 확인합니다."""
        hashes = self._read_password_db()

        if not hashes:
            return TestResult(
                id="CRYPT-006",
                name="솔트(Salt) 적용",
                category="암호화",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="패스워드 데이터베이스를 읽을 수 없습니다.",
                timestamp=datetime.now(),
            )

        # bcrypt, sha512_crypt 등은 솔트가 내장됨
        salted_formats = {"bcrypt", "sha512_crypt", "sha256_crypt", "pbkdf2_sha256", "argon2"}
        has_salt = False

        for h in hashes:
            fmt = identify_hash_format(h)
            if fmt in salted_formats:
                has_salt = True
                break

        if has_salt:
            return TestResult(
                id="CRYPT-006",
                name="솔트(Salt) 적용",
                category="암호화",
                status=TestStatus.PASS,
                engine=self.engine,
                details="패스워드 해시에 솔트가 적용되어 있습니다.",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="CRYPT-006",
            name="솔트(Salt) 적용",
            category="암호화",
            status=TestStatus.MANUAL,
            engine=self.engine,
            details="솔트 적용 여부를 자동으로 확인할 수 없습니다. 수동 확인이 필요합니다.",
            timestamp=datetime.now(),
        )

    def check_pbkdf2_iterations(self) -> TestResult:
        """PBKDF2 반복 횟수가 10,000회 이상인지 확인합니다."""
        hashes = self._read_password_db()

        pbkdf2_pattern = re.compile(r"pbkdf2_sha256\$(\d+)\$")

        for h in hashes:
            match = pbkdf2_pattern.search(h)
            if match:
                iterations = int(match.group(1))
                if iterations < MIN_PBKDF2_ITERATIONS:
                    return TestResult(
                        id="CRYPT-007",
                        name="PBKDF2 반복횟수 10,000회 이상",
                        category="암호화",
                        status=TestStatus.FAIL,
                        engine=self.engine,
                        details=f"PBKDF2 반복 횟수가 {iterations}회로 너무 낮습니다. {MIN_PBKDF2_ITERATIONS}회 이상이어야 합니다.",
                        timestamp=datetime.now(),
                    )
                return TestResult(
                    id="CRYPT-007",
                    name="PBKDF2 반복횟수 10,000회 이상",
                    category="암호화",
                    status=TestStatus.PASS,
                    engine=self.engine,
                    details=f"PBKDF2 반복 횟수: {iterations}회",
                    timestamp=datetime.now(),
                )

        return TestResult(
            id="CRYPT-007",
            name="PBKDF2 반복횟수 10,000회 이상",
            category="암호화",
            status=TestStatus.SKIP,
            engine=self.engine,
            details="PBKDF2 해시를 찾을 수 없습니다. 다른 해시 알고리즘을 사용하고 있을 수 있습니다.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """해시 관련 검사를 모두 실행합니다."""
        return [
            self.check_hash_format(),
            self.check_salt_usage(),
            self.check_pbkdf2_iterations(),
        ]
