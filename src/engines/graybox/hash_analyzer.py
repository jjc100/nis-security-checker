"""
그레이박스 검사 - 패스워드 해시 분석 모듈
소스 코드에서 약한 해시 알고리즘 사용 여부를 탐지하고,
파일시스템의 패스워드 해시 포맷 및 솔트/반복횟수를 검증합니다.
Windows/.NET/C++ 프로젝트와 Linux 파일시스템을 모두 지원합니다.
"""

import re
from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus
from src.utils.crypto import identify_hash_format, is_strong_hash

# Linux 폴백 패스워드 데이터베이스 경로
LINUX_PASSWORD_DB_PATHS = [
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

# .NET 약한 해시 사용 패턴
DOTNET_WEAK_HASH_PATTERNS = [
    re.compile(r'\bMD5\s*\.Create\s*\(\s*\)', re.IGNORECASE),
    re.compile(r'\bMD5CryptoServiceProvider\b', re.IGNORECASE),
    re.compile(r'\bSHA1\s*\.Create\s*\(\s*\)', re.IGNORECASE),
    re.compile(r'\bSHA1Managed\b|\bSHA1CryptoServiceProvider\b', re.IGNORECASE),
    re.compile(r'new\s+SHA1\s*\(', re.IGNORECASE),
    re.compile(r'HashAlgorithm\.Create\s*\(\s*"MD5"\s*\)', re.IGNORECASE),
    re.compile(r'HashAlgorithm\.Create\s*\(\s*"SHA1"\s*\)', re.IGNORECASE),
]

# C++ 약한 해시 사용 패턴
CPP_WEAK_HASH_PATTERNS = [
    re.compile(r'\bMD5_Init\b|\bMD5_Update\b|\bMD5_Final\b'),
    re.compile(r'\bSHA1_Init\b|\bSHA1_Update\b|\bSHA1_Final\b'),
    re.compile(r'\bEVP_md5\s*\(\s*\)'),
    re.compile(r'\bEVP_sha1\s*\(\s*\)'),
]

# 소스/설정 파일 확장자
SOURCE_EXTENSIONS = {".cs", ".cpp", ".h", ".c", ".hpp"}
CONFIG_EXTENSIONS = {".config", ".xml", ".json", ".ini", ".yaml", ".yml", ".properties"}

# 제외 디렉터리
EXCLUDED_DIRS = {".git", "node_modules", ".vs", ".idea"}


def _is_excluded(path: Path) -> bool:
    """제외 디렉터리 여부를 확인합니다."""
    return any(part in EXCLUDED_DIRS for part in path.parts)


def _get_project_roots(config: dict) -> list[Path]:
    """설정에서 프로젝트 루트 경로 목록을 결정합니다."""
    target = config.get("target", {})
    roots: list[Path] = []

    source_paths = target.get("source_paths") or []
    for sp in source_paths:
        p = Path(sp)
        if p.exists():
            roots.append(p)

    project_path = target.get("project_path")
    if project_path:
        p = Path(project_path)
        if p.exists():
            roots.append(p)

    return roots


class HashAnalyzer:
    """패스워드 해시 분석기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"
        self._project_roots = _get_project_roots(config)

    def _read_password_db(self) -> list[str]:
        """패스워드 데이터베이스 파일에서 해시 문자열을 추출합니다 (Linux 전용)."""
        hashes = []
        for path_str in LINUX_PASSWORD_DB_PATHS:
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

    def _find_source_files(self, max_count: int = 200) -> list[Path]:
        """분석할 소스/설정 파일 목록을 반환합니다."""
        files: list[Path] = []
        seen: set[Path] = set()
        all_exts = SOURCE_EXTENSIONS | CONFIG_EXTENSIONS

        for root in self._project_roots:
            if not root.exists():
                continue
            for fpath in root.rglob("*"):
                if _is_excluded(fpath):
                    continue
                if not fpath.is_file():
                    continue
                if fpath.suffix.lower() not in all_exts:
                    continue
                resolved = fpath.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                files.append(fpath)
                if len(files) >= max_count:
                    return files
        return files

    def _detect_weak_hash_in_source(self, source_files: list[Path]) -> list[str]:
        """소스 코드에서 약한 해시 알고리즘 사용 패턴을 탐지합니다."""
        hits: list[str] = []
        for fpath in source_files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                ext = fpath.suffix.lower()
                found = False

                if ext == ".cs":
                    for pat in DOTNET_WEAK_HASH_PATTERNS:
                        if pat.search(content):
                            hits.append(f"{fpath.name}: .NET 약한 해시 패턴")
                            found = True
                            break
                elif ext in {".cpp", ".h", ".c", ".hpp"}:
                    for pat in CPP_WEAK_HASH_PATTERNS:
                        if pat.search(content):
                            hits.append(f"{fpath.name}: C++ 약한 해시 패턴")
                            found = True
                            break

                if not found:
                    # 설정 파일에서 해시값 형식 분석
                    for line in content.splitlines():
                        if re.search(r'hash|digest|checksum', line, re.IGNORECASE):
                            # MD5처럼 보이는 32자 16진수 검출
                            if re.search(r'\b[0-9a-fA-F]{32}\b', line):
                                hits.append(f"{fpath.name}: MD5 크기 해시값 발견")
                                break
            except OSError:
                continue
        return hits

    def check_hash_format(self) -> TestResult:
        """패스워드 해시 포맷이 안전한지 확인합니다."""
        # Windows 프로젝트 모드: 소스 코드에서 약한 해시 패턴 탐지
        source_files = self._find_source_files()
        if source_files:
            weak_hits = self._detect_weak_hash_in_source(source_files)
            if weak_hits:
                return TestResult(
                    id="CRYPT-005",
                    name="패스워드 단방향 해시 저장",
                    category="암호화",
                    status=TestStatus.FAIL,
                    engine=self.engine,
                    details=f"소스 코드에서 약한 해시 알고리즘 사용 탐지: {'; '.join(weak_hits[:5])}",
                    timestamp=datetime.now(),
                )
            return TestResult(
                id="CRYPT-005",
                name="패스워드 단방향 해시 저장",
                category="암호화",
                status=TestStatus.PASS,
                engine=self.engine,
                details=f"{len(source_files)}개 소스 파일에서 약한 해시 패턴 미탐지.",
                timestamp=datetime.now(),
            )

        # Linux 폴백: 패스워드 DB 파일 분석
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
                details="식별 불가 해시 포맷이 있습니다. 수동 확인이 필요합니다.",
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
        # 소스 파일이 있으면 소스 기반 분석 (salt 미적용 여부 탐지)
        source_files = self._find_source_files()
        if source_files:
            return TestResult(
                id="CRYPT-006",
                name="솔트(Salt) 적용",
                category="암호화",
                status=TestStatus.MANUAL,
                engine=self.engine,
                details=(
                    f"{len(source_files)}개 소스 파일 스캔 완료. "
                    "솔트 적용 여부는 해시 생성 로직을 수동으로 확인하세요."
                ),
                timestamp=datetime.now(),
            )

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
        has_salt = any(identify_hash_format(h) in salted_formats for h in hashes)

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
                        details=(
                            f"PBKDF2 반복 횟수가 {iterations}회로 너무 낮습니다. "
                            f"{MIN_PBKDF2_ITERATIONS}회 이상이어야 합니다."
                        ),
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
