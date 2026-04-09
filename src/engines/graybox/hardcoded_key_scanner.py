"""
그레이박스 검사 - 하드코딩 암호키 탐지 모듈
소스 파일 및 바이너리에서 하드코딩된 키/패스워드/시크릿을 탐지합니다.
Windows/.NET/C++ 프로젝트와 Linux 바이너리를 모두 지원합니다.
"""

import base64
import re
from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus
from src.utils.crypto import calculate_entropy
from src.utils.path_validator import is_within_root, DEFAULT_EXCLUDE_DIRS, DEFAULT_MAX_DEPTH

# 하드코딩 키 패턴 (PEM 헤더, API 키, 시크릿 등)
KEY_PATTERNS = [
    re.compile(r'-----BEGIN (RSA |EC |DSA |PRIVATE |OPENSSH )?PRIVATE KEY-----'),
    re.compile(r'-----BEGIN CERTIFICATE-----'),
    re.compile(r'AES_KEY\s*[=:]\s*["\']([A-Za-z0-9+/=]{24,})["\']', re.IGNORECASE),
    re.compile(r'SECRET_KEY\s*[=:]\s*["\']([^"\']{16,})["\']', re.IGNORECASE),
    re.compile(r'ENCRYPTION_KEY\s*[=:]\s*["\']([^"\']{16,})["\']', re.IGNORECASE),
    re.compile(r'PRIVATE_KEY\s*[=:]\s*["\']([^"\']{16,})["\']', re.IGNORECASE),
    re.compile(r'api_?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.IGNORECASE),
]

# .NET connectionString / appSettings 내 하드코딩 패턴
DOTNET_HARDCODED_PATTERNS = [
    re.compile(r'connectionString\s*=\s*"[^"]*password=([^;"\s]{4,})', re.IGNORECASE),
    re.compile(r'<add\s+key="[^"]*(?:password|secret|key|token)[^"]*"\s+value="([^"]{4,})"', re.IGNORECASE),
    re.compile(r'AppSettings\["[^"]*(?:password|secret|key|api)[^"]*"\]\s*=\s*"([^"]{4,})"', re.IGNORECASE),
]

# 소스 파일 확장자
SOURCE_EXTENSIONS = {".cs", ".cpp", ".h", ".c", ".hpp"}
CONFIG_EXTENSIONS = {".config", ".xml", ".json", ".ini", ".yaml", ".yml"}
BINARY_EXTENSIONS = {".dll", ".exe", ".lib", ".obj"}

# 제외 디렉터리
EXCLUDED_DIRS = DEFAULT_EXCLUDE_DIRS

# Linux 폴백 디렉터리
LINUX_SCAN_DIRS = ["/opt", "/usr/local/bin", "/usr/local/lib"]

# 엔트로피 임계값 (높은 값 = 랜덤 데이터 가능성)
ENTROPY_THRESHOLD = 7.0

# 최소 Base64 문자열 길이 (24자 이상 = 18바이트)
MIN_B64_LENGTH = 24


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

    if target.get("scan_build_outputs", True):
        build_output = target.get("build_output_path")
        if build_output:
            p = Path(build_output)
            if p.exists():
                roots.append(p)

    return roots


def _extract_strings_from_binary(data: bytes, min_length: int = 8) -> list[str]:
    """바이너리 데이터에서 ASCII 가독 문자열을 추출합니다 (Python 순수 구현)."""
    results: list[str] = []
    current: list[int] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(byte)
        else:
            if len(current) >= min_length:
                results.append(bytes(current).decode("ascii", errors="ignore"))
            current = []
    if len(current) >= min_length:
        results.append(bytes(current).decode("ascii", errors="ignore"))
    return results


class HardcodedKeyScanner:
    """하드코딩 암호키 탐지기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"
        self._project_roots = _get_project_roots(config)

    def _get_strings(self, filepath: str, min_len: int = 8) -> list[str]:
        """바이너리에서 가독 문자열을 추출합니다 (Python 순수 구현)."""
        try:
            with open(filepath, "rb") as f:
                data = f.read(4 * 1024 * 1024)  # 최대 4MB
            return _extract_strings_from_binary(data, min_len)
        except OSError:
            return []

    def _is_high_entropy_b64(self, s: str) -> bool:
        """Base64처럼 보이고 엔트로피가 높은 문자열인지 확인합니다."""
        b64_pattern = re.compile(r'^[A-Za-z0-9+/]{' + str(MIN_B64_LENGTH) + r',}={0,2}$')
        if not b64_pattern.match(s):
            return False
        try:
            decoded = base64.b64decode(s + "==")
            return calculate_entropy(decoded) >= ENTROPY_THRESHOLD
        except Exception:
            return False

    def _find_source_files(self, max_count: int = 300) -> list[Path]:
        """분석할 소스/설정 파일 목록을 반환합니다."""
        files: list[Path] = []
        seen: set[Path] = set()
        all_exts = SOURCE_EXTENSIONS | CONFIG_EXTENSIONS

        for root in self._project_roots:
            if not root.exists():
                continue
            resolved_root = root.resolve()
            for fpath in root.rglob("*"):
                if _is_excluded(fpath):
                    continue
                if not fpath.is_file():
                    continue
                if fpath.suffix.lower() not in all_exts:
                    continue
                # 스캔 깊이 제한
                try:
                    depth = len(fpath.relative_to(root).parts)
                    if depth > DEFAULT_MAX_DEPTH:
                        continue
                except ValueError:
                    continue
                resolved = fpath.resolve()
                # 루트 바깥 경로(심볼릭 링크 우회 등) 방지
                if not is_within_root(resolved, resolved_root):
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                files.append(fpath)
                if len(files) >= max_count:
                    return files
        return files

    def _find_binaries(self, max_count: int = 20) -> list[Path]:
        """분석할 바이너리 파일 목록을 반환합니다."""
        binaries: list[Path] = []
        seen: set[Path] = set()

        for root in self._project_roots:
            if not root.exists():
                continue
            resolved_root = root.resolve()
            for fpath in root.rglob("*"):
                if _is_excluded(fpath):
                    continue
                if not fpath.is_file():
                    continue
                if fpath.suffix.lower() not in BINARY_EXTENSIONS:
                    continue
                # 스캔 깊이 제한
                try:
                    depth = len(fpath.relative_to(root).parts)
                    if depth > DEFAULT_MAX_DEPTH:
                        continue
                except ValueError:
                    continue
                resolved = fpath.resolve()
                # 루트 바깥 경로(심볼릭 링크 우회 등) 방지
                if not is_within_root(resolved, resolved_root):
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                binaries.append(fpath)
                if len(binaries) >= max_count:
                    return binaries

        # Windows 프로젝트 설정이 없으면 Linux 폴백
        if not binaries and not self._project_roots:
            for dir_str in LINUX_SCAN_DIRS:
                dir_path = Path(dir_str)
                if not dir_path.exists():
                    continue
                for fpath in dir_path.rglob("*"):
                    if fpath.is_file() and not fpath.suffix:
                        binaries.append(fpath)
                        if len(binaries) >= max_count:
                            return binaries

        return binaries

    def _scan_source_file(self, fpath: Path) -> list[str]:
        """단일 소스/설정 파일에서 하드코딩 키 패턴을 탐지합니다."""
        found: list[str] = []
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")

            # 공통 키 패턴 검사
            for pattern in KEY_PATTERNS:
                if pattern.search(content):
                    found.append(f"{fpath.name}: 키 패턴 탐지")
                    break

            # .NET config/xml 전용 패턴
            if fpath.suffix.lower() in {".config", ".xml"}:
                for pattern in DOTNET_HARDCODED_PATTERNS:
                    matches = pattern.findall(content)
                    if matches:
                        found.append(f"{fpath.name}: .NET 하드코딩 값 탐지")
                        break

            # 고엔트로피 Base64 문자열 탐지 (소스 내 리터럴)
            for line in content.splitlines():
                # 따옴표 안의 문자열만 추출
                for m in re.finditer(r'["\']([A-Za-z0-9+/]{24,}={0,2})["\']', line):
                    if self._is_high_entropy_b64(m.group(1)):
                        found.append(f"{fpath.name}: 고엔트로피 문자열 ({m.group(1)[:20]}...)")
                        break

        except OSError:
            pass
        return found

    def check_hardcoded_keys(self) -> TestResult:
        """소스 파일 및 바이너리에서 하드코딩된 암호키를 탐지합니다."""
        source_files = self._find_source_files()
        binaries = self._find_binaries()

        if not source_files and not binaries:
            return TestResult(
                id="CRYPT-008",
                name="하드코딩 암호키 미존재",
                category="암호화",
                status=TestStatus.SKIP,
                engine=self.engine,
                details=(
                    "분석할 소스 파일 또는 바이너리를 찾을 수 없습니다. "
                    "config의 project_path 또는 scan_paths를 확인하세요."
                ),
                timestamp=datetime.now(),
            )

        found_keys: list[str] = []

        # 소스 파일 분석
        for fpath in source_files:
            found_keys.extend(self._scan_source_file(fpath))

        # 바이너리 분석
        for binary in binaries:
            strings = self._get_strings(str(binary))
            for s in strings:
                for pattern in KEY_PATTERNS:
                    if pattern.search(s):
                        found_keys.append(f"{binary.name}: 키 패턴 탐지")
                        break
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

        total = len(source_files) + len(binaries)
        return TestResult(
            id="CRYPT-008",
            name="하드코딩 암호키 미존재",
            category="암호화",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"{total}개 파일에서 하드코딩 키 미탐지.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """하드코딩 키 관련 검사를 모두 실행합니다."""
        return [self.check_hardcoded_keys()]
