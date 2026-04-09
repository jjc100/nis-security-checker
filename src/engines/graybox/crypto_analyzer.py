"""
그레이박스 검사 - 암호화 알고리즘 분석 모듈
소스 파일 및 바이너리에서 금지 암호 알고리즘 사용 여부를 확인합니다.
Windows/.NET/C++ 프로젝트와 Linux 바이너리를 모두 지원합니다.
"""

import re
from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus
from src.utils.crypto import is_weak_algorithm

# Linux 폴백 바이너리 탐색 경로
LINUX_BINARY_PATHS = [
    "/usr/lib",
    "/usr/local/lib",
    "/opt",
    "/usr/sbin",
    "/usr/bin",
]

# 바이너리 파일 확장자 (Windows 산출물 포함)
BINARY_EXTENSIONS = {".so", ".dll", ".exe", ".lib", ".obj"}

# 소스 파일 확장자
SOURCE_EXTENSIONS = {".cs", ".cpp", ".h", ".c", ".hpp"}

# 설정/리소스 파일 확장자
CONFIG_EXTENSIONS = {".config", ".xml", ".json", ".ini", ".yaml", ".yml"}

# 제외 디렉터리
EXCLUDED_DIRS = {".git", "node_modules", ".vs", ".idea"}

# .NET 금지 알고리즘 네임스페이스/클래스 패턴
DOTNET_FORBIDDEN_PATTERNS = [
    re.compile(r'System\.Security\.Cryptography\.MD5', re.IGNORECASE),
    re.compile(r'\bMD5\s*\.Create\s*\(\s*\)', re.IGNORECASE),
    re.compile(r'\bMD5CryptoServiceProvider\b', re.IGNORECASE),
    re.compile(r'\bSHA1\s*\.Create\s*\(\s*\)', re.IGNORECASE),
    re.compile(r'\bSHA1Managed\b|\bSHA1CryptoServiceProvider\b', re.IGNORECASE),
    re.compile(r'\bDESCryptoServiceProvider\b|\bTripleDESCryptoServiceProvider\b', re.IGNORECASE),
    re.compile(r'\bRC2CryptoServiceProvider\b', re.IGNORECASE),
    re.compile(r'CipherMode\.ECB\b', re.IGNORECASE),
]

# C++ 금지 알고리즘 패턴 (OpenSSL, WinCrypt 등)
CPP_FORBIDDEN_PATTERNS = [
    re.compile(r'\bEVP_des_\w+\b'),
    re.compile(r'\bEVP_rc4\b'),
    re.compile(r'\bDES_ecb_encrypt\b|\bDES_cbc_encrypt\b'),
    re.compile(r'\bRC4_set_key\b|\bRC4\s*\('),
    re.compile(r'\bMD5_Init\b|\bMD5_Update\b|\bMD5_Final\b'),
    re.compile(r'\bSHA1_Init\b|\bSHA1_Update\b|\bSHA1_Final\b'),
]


def _extract_strings_from_binary(data: bytes, min_length: int = 6) -> list[str]:
    """바이너리 데이터에서 ASCII/UTF-8 가독 문자열을 추출합니다 (Python 순수 구현)."""
    results = []
    current: list[int] = []
    for byte in data:
        # 출력 가능한 ASCII 문자 (0x20~0x7e)
        if 0x20 <= byte <= 0x7E:
            current.append(byte)
        else:
            if len(current) >= min_length:
                results.append(bytes(current).decode("ascii", errors="ignore"))
            current = []
    if len(current) >= min_length:
        results.append(bytes(current).decode("ascii", errors="ignore"))
    return results


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


class CryptoAnalyzer:
    """암호화 알고리즘 분석기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"
        self._project_roots = _get_project_roots(config)

    def _get_strings(self, filepath: str, min_length: int = 6) -> list[str]:
        """바이너리 파일에서 가독 문자열을 추출합니다 (Python 순수 구현)."""
        try:
            with open(filepath, "rb") as f:
                data = f.read(4 * 1024 * 1024)  # 최대 4MB
            return _extract_strings_from_binary(data, min_length)
        except OSError:
            return []

    def _find_source_files(self, max_count: int = 200) -> list[Path]:
        """분석할 소스 파일 목록을 반환합니다."""
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

    def _find_binaries(self, max_count: int = 20) -> list[Path]:
        """분석할 바이너리 파일 목록을 반환합니다."""
        binaries: list[Path] = []
        seen: set[Path] = set()

        # Windows 프로젝트 루트에서 바이너리 탐색
        for root in self._project_roots:
            if not root.exists():
                continue
            for fpath in root.rglob("*"):
                if _is_excluded(fpath):
                    continue
                if not fpath.is_file():
                    continue
                if fpath.suffix.lower() not in BINARY_EXTENSIONS:
                    continue
                resolved = fpath.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                binaries.append(fpath)
                if len(binaries) >= max_count:
                    return binaries

        # Windows 프로젝트 설정이 없으면 Linux 경로 폴백
        if not binaries and not self._project_roots:
            for path_str in LINUX_BINARY_PATHS:
                path = Path(path_str)
                if not path.exists():
                    continue
                for fpath in path.rglob("*.so*"):
                    if fpath.is_file():
                        resolved = fpath.resolve()
                        if resolved not in seen:
                            seen.add(resolved)
                            binaries.append(fpath)
                            if len(binaries) >= max_count:
                                return binaries

        return binaries

    def _check_source_for_forbidden(self, source_files: list[Path]) -> dict[str, list[str]]:
        """소스 파일에서 금지 암호 알고리즘 패턴을 탐지합니다."""
        found: dict[str, list[str]] = {}
        for fpath in source_files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                detected: list[str] = []
                ext = fpath.suffix.lower()

                if ext in {".cs"}:
                    for pat in DOTNET_FORBIDDEN_PATTERNS:
                        if pat.search(content):
                            detected.append(pat.pattern[:30])
                elif ext in {".cpp", ".h", ".c", ".hpp"}:
                    for pat in CPP_FORBIDDEN_PATTERNS:
                        if pat.search(content):
                            detected.append(pat.pattern[:30])

                # 모든 소스/설정 파일에 대해 키워드 탐지
                weak = is_weak_algorithm(content)
                detected.extend(weak)

                if detected:
                    found[fpath.name] = list(set(detected))
            except OSError:
                continue
        return found

    def check_forbidden_algorithms(self) -> TestResult:
        """소스/바이너리에서 금지 암호 알고리즘 사용 여부를 확인합니다."""
        source_files = self._find_source_files()
        binaries = self._find_binaries()

        if not source_files and not binaries:
            return TestResult(
                id="CRYPT-004",
                name="금지 암호 알고리즘 미사용",
                category="암호화",
                status=TestStatus.SKIP,
                engine=self.engine,
                details=(
                    "분석할 소스 파일 또는 바이너리를 찾을 수 없습니다. "
                    "config의 project_path 또는 scan_paths를 확인하세요."
                ),
                timestamp=datetime.now(),
            )

        found_weak: dict[str, list[str]] = {}

        # 소스 파일 분석
        source_found = self._check_source_for_forbidden(source_files)
        found_weak.update(source_found)

        # 바이너리 분석 (Python 순수 문자열 추출)
        for binary in binaries:
            strings = self._get_strings(str(binary))
            all_text = " ".join(strings)
            weak_algos = is_weak_algorithm(all_text)
            if weak_algos:
                found_weak[binary.name] = weak_algos

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

        total = len(source_files) + len(binaries)
        return TestResult(
            id="CRYPT-004",
            name="금지 암호 알고리즘 미사용",
            category="암호화",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"{total}개 파일 분석 완료. 금지 알고리즘 미탐지.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """암호화 알고리즘 관련 검사를 모두 실행합니다."""
        return [self.check_forbidden_algorithms()]
