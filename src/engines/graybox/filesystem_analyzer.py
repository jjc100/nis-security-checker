"""
그레이박스 검사 - 파일시스템 분석 모듈
설정 파일 탐색, 파일 권한 검사, 평문 패스워드 탐지를 수행합니다.
"""

import os
import re
import stat
from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus

# 주요 설정 파일 경로 패턴
CONFIG_FILE_PATTERNS = [
    "*.conf", "*.cfg", "*.ini", "*.yaml", "*.yml",
    "*.json", "*.xml", "*.properties", "*.env",
]

# 검색할 루트 디렉토리
SEARCH_ROOTS = ["/etc", "/opt", "/var/lib", "/usr/local/etc"]

# 평문 패스워드 패턴 (정규식)
PLAINTEXT_PASSWORD_PATTERNS = [
    re.compile(r'password\s*[=:]\s*["\']?([^"\'\\n\s]{4,})["\']?', re.IGNORECASE),
    re.compile(r'passwd\s*[=:]\s*["\']?([^"\'\\n\s]{4,})["\']?', re.IGNORECASE),
    re.compile(r'pwd\s*[=:]\s*["\']?([^"\'\\n\s]{4,})["\']?', re.IGNORECASE),
    re.compile(r'secret\s*[=:]\s*["\']?([^"\'\\n\s]{4,})["\']?', re.IGNORECASE),
]

# 안전한 권한 (소유자만 읽기/쓰기 가능)
SAFE_PERMISSIONS = {stat.S_IRUSR, stat.S_IWUSR}


class FilesystemAnalyzer:
    """파일시스템 보안 분석기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"

    def _find_config_files(self, max_files: int = 200) -> list[Path]:
        """설정 파일을 탐색하여 경로 목록을 반환합니다."""
        found = []
        for root_dir in SEARCH_ROOTS:
            root = Path(root_dir)
            if not root.exists():
                continue
            for pattern in CONFIG_FILE_PATTERNS:
                for fpath in root.rglob(pattern):
                    if fpath.is_file():
                        found.append(fpath)
                        if len(found) >= max_files:
                            return found
        return found

    def check_file_permissions(self) -> TestResult:
        """주요 설정 파일의 접근 권한이 적절한지 확인합니다."""
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
        """설정 파일에 평문 패스워드가 저장되어 있는지 확인합니다."""
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
            details=f"{len(config_files)}개 설정 파일에서 평문 패스워드 미탐지.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """파일시스템 관련 검사를 모두 실행합니다."""
        return [
            self.check_file_permissions(),
            self.check_plaintext_passwords(),
        ]
