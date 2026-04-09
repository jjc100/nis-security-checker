"""
그레이박스 검사 - 파일시스템 분석 모듈
설정 파일 탐색, 파일 권한 검사, 평문 패스워드 탐지를 수행합니다.
Windows/.NET/C++ 프로젝트와 Linux 파일시스템을 모두 지원합니다.
"""

import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus
from src.utils.path_validator import is_within_root, DEFAULT_EXCLUDE_DIRS, DEFAULT_MAX_FILES, DEFAULT_MAX_DEPTH

# 소스/설정 파일 확장자 (Windows 프로젝트 친화적)
SOURCE_EXTENSIONS = {
    ".cs", ".cpp", ".h", ".c", ".hpp",
    ".config", ".json", ".xml", ".ini",
    ".yaml", ".yml", ".txt", ".properties",
    ".resx", ".env",
}

# 빌드 산출물 확장자
BUILD_OUTPUT_EXTENSIONS = {".dll", ".exe", ".pdb", ".lib", ".obj"}

# Linux 폴백 탐색 루트 (project_path 미설정 시)
LINUX_SEARCH_ROOTS = ["/etc", "/opt", "/var/lib", "/usr/local/etc"]

# 제외 디렉터리 이름
EXCLUDED_DIRS = DEFAULT_EXCLUDE_DIRS

# 평문 패스워드 패턴 (정규식)
PLAINTEXT_PASSWORD_PATTERNS = [
    re.compile(r'password\s*[=:]\s*["\']?([^"\'\\n\s]{4,})["\']?', re.IGNORECASE),
    re.compile(r'passwd\s*[=:]\s*["\']?([^"\'\\n\s]{4,})["\']?', re.IGNORECASE),
    re.compile(r'pwd\s*[=:]\s*["\']?([^"\'\\n\s]{4,})["\']?', re.IGNORECASE),
    re.compile(r'secret\s*[=:]\s*["\']?([^"\'\\n\s]{4,})["\']?', re.IGNORECASE),
    # .NET connectionString / appSettings 패턴
    re.compile(r'connectionString[^"]*"[^"]*password=([^;"\s]{4,})', re.IGNORECASE),
    # XML 속성: key="password" value="mysecret123"
    re.compile(r'key\s*=\s*"[^"]*(?:password|secret|passwd)[^"]*"\s+value\s*=\s*"([^"]{4,})"', re.IGNORECASE),
]

# 안전한 권한 (소유자만 읽기/쓰기 가능, Linux 전용)
_SAFE_PERMISSIONS = {stat.S_IRUSR, stat.S_IWUSR}


def _get_scan_roots(config: dict) -> list[Path]:
    """설정에서 탐색할 루트 경로 목록을 결정합니다."""
    target = config.get("target", {})
    roots: list[Path] = []
    has_windows_config = False  # Windows 프로젝트 설정 존재 여부

    # source_paths가 명시된 경우 우선 사용
    source_paths = target.get("source_paths") or []
    for sp in source_paths:
        has_windows_config = True
        p = Path(sp)
        if p.exists():
            roots.append(p)

    # project_path가 있으면 루트로 추가
    project_path = target.get("project_path")
    if project_path:
        has_windows_config = True
        p = Path(project_path)
        if p.exists():
            roots.append(p)

    # build_output_path가 있고 scan_build_outputs가 true면 포함
    if target.get("scan_build_outputs", True):
        build_output = target.get("build_output_path")
        if build_output:
            has_windows_config = True
            p = Path(build_output)
            if p.exists():
                roots.append(p)

    # Windows 프로젝트 설정이 전혀 없는 경우에만 Linux 폴백 사용
    if not has_windows_config:
        for path_str in LINUX_SEARCH_ROOTS:
            p = Path(path_str)
            if p.exists():
                roots.append(p)

    return roots


def _is_excluded(path: Path) -> bool:
    """제외 디렉터리 여부를 확인합니다."""
    return any(part in EXCLUDED_DIRS for part in path.parts)


class FilesystemAnalyzer:
    """파일시스템 보안 분석기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"
        self._scan_roots = _get_scan_roots(config)

    def _find_config_files(self, max_files: int = 300) -> list[Path]:
        """설정/소스 파일을 탐색하여 경로 목록을 반환합니다."""
        found: list[Path] = []
        seen: set[Path] = set()

        for root in self._scan_roots:
            if not root.exists():
                continue
            resolved_root = root.resolve()
            for fpath in root.rglob("*"):
                if _is_excluded(fpath):
                    continue
                if not fpath.is_file():
                    continue
                if fpath.suffix.lower() not in SOURCE_EXTENSIONS:
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
                found.append(fpath)
                if len(found) >= max_files:
                    return found
        return found

    def check_file_permissions(self) -> TestResult:
        """주요 설정 파일의 접근 권한이 적절한지 확인합니다."""
        # Windows에서는 ACL 기반이므로 POSIX 권한 검사를 건너뜀
        if sys.platform == "win32":
            return TestResult(
                id="FS-001",
                name="설정 파일 접근 권한 제한",
                category="파일시스템",
                status=TestStatus.MANUAL,
                engine=self.engine,
                details="Windows 환경에서는 ACL 기반 파일 권한을 수동으로 확인하세요.",
                timestamp=datetime.now(),
            )

        config_files = self._find_config_files()

        if not config_files:
            return TestResult(
                id="FS-001",
                name="설정 파일 접근 권한 제한",
                category="파일시스템",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="설정 파일을 찾을 수 없습니다. 접근 권한이 필요하거나 경로가 다를 수 있습니다.",
                timestamp=datetime.now(),
            )

        insecure_files = []
        for fpath in config_files:
            try:
                file_stat = os.stat(fpath)
                mode = file_stat.st_mode
                # 그룹 또는 기타 사용자에게 쓰기 권한이 있으면 취약
                if mode & (stat.S_IWGRP | stat.S_IWOTH):
                    insecure_files.append(str(fpath))
            except OSError:
                continue

        if insecure_files:
            return TestResult(
                id="FS-001",
                name="설정 파일 접근 권한 제한",
                category="파일시스템",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"그룹/기타 쓰기 권한이 있는 설정 파일: {', '.join(insecure_files[:5])}",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="FS-001",
            name="설정 파일 접근 권한 제한",
            category="파일시스템",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"{len(config_files)}개 설정 파일 권한 검사 완료. 취약 파일 없음.",
            timestamp=datetime.now(),
        )

    def check_plaintext_passwords(self) -> TestResult:
        """설정/소스 파일에 평문 패스워드가 저장되어 있는지 확인합니다."""
        config_files = self._find_config_files()
        found_files = []

        for fpath in config_files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for pattern in PLAINTEXT_PASSWORD_PATTERNS:
                    matches = pattern.findall(content)
                    # 해시값처럼 보이는 경우 제외 (긴 16진수 문자열)
                    real_passwords = [
                        m for m in matches
                        if not re.match(r'^[0-9a-fA-F]{32,}$', m)
                        and not m.startswith("$")
                        and m.lower() not in ("", "null", "none", "empty", "placeholder")
                    ]
                    if real_passwords:
                        found_files.append(str(fpath))
                        break
            except OSError:
                continue

        if found_files:
            return TestResult(
                id="FS-002",
                name="평문 패스워드 설정 파일 저장 금지",
                category="파일시스템",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"평문 패스워드가 포함된 파일: {', '.join(found_files[:5])}",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="FS-002",
            name="평문 패스워드 설정 파일 저장 금지",
            category="파일시스템",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"{len(config_files)}개 파일에서 평문 패스워드 미탐지.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """파일시스템 관련 검사를 모두 실행합니다."""
        return [
            self.check_file_permissions(),
            self.check_plaintext_passwords(),
        ]
