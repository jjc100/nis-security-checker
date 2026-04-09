"""
그레이박스 검사 - 감사로그 분석 모듈
감사로그 필수 이벤트/필드 확인, 민감정보 미포함 여부를 검사합니다.
"""

import re
from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus

# 감사로그 파일 경로
LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/audit/audit.log",
    "/var/log/nvr/audit.log",
    "/var/log/camera/access.log",
    "/opt/nvr/logs/audit.log",
]

# 필수 로그 이벤트 키워드
REQUIRED_EVENTS = {
    "로그인_성공": ["Accepted", "login", "authentication successful", "로그인 성공"],
    "로그인_실패": ["Failed", "failure", "authentication failure", "로그인 실패"],
}

# 필수 로그 필드 패턴
REQUIRED_FIELDS = {
    "타임스탬프": re.compile(r'\d{4}-\d{2}-\d{2}|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}'),
    "IP주소": re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    "사용자ID": re.compile(r'user=\w+|username=\w+|사용자[=:]\s*\w+', re.IGNORECASE),
}

# 로그에 포함되면 안 되는 민감정보 패턴
SENSITIVE_PATTERNS = [
    re.compile(r'password[=:\s]+[^\s]{4,}', re.IGNORECASE),
    re.compile(r'passwd[=:\s]+[^\s]{4,}', re.IGNORECASE),
    re.compile(r'secret[=:\s]+[^\s]{4,}', re.IGNORECASE),
    re.compile(r'token[=:\s]+[a-zA-Z0-9+/=]{20,}', re.IGNORECASE),
]


class LogAnalyzer:
    """감사로그 분석기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"

    def _find_log_file(self) -> Path | None:
        """존재하는 로그 파일을 반환합니다."""
        for path_str in LOG_PATHS:
            path = Path(path_str)
            if path.exists() and path.is_file():
                return path
        return None

    def _read_log_tail(self, path: Path, lines: int = 500) -> list[str]:
        """로그 파일의 마지막 N줄을 읽습니다."""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            all_lines = content.splitlines()
            return all_lines[-lines:]
        except OSError:
            return []

    def check_required_events(self) -> TestResult:
        """필수 이벤트(로그인 성공/실패)가 감사로그에 기록되는지 확인합니다."""
        log_file = self._find_log_file()

        if not log_file:
            return TestResult(
                id="LOG-001",
                name="로그인 성공/실패 이벤트 기록",
                category="감사로그",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="감사로그 파일을 찾을 수 없습니다. 접근 권한이 필요할 수 있습니다.",
                timestamp=datetime.now(),
            )

        log_lines = self._read_log_tail(log_file)
        log_text = "\n".join(log_lines).lower()

        missing_events = []
        for event_name, keywords in REQUIRED_EVENTS.items():
            found = any(kw.lower() in log_text for kw in keywords)
            if not found:
                missing_events.append(event_name)

        if missing_events:
            return TestResult(
                id="LOG-001",
                name="로그인 성공/실패 이벤트 기록",
                category="감사로그",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"감사로그에 누락된 이벤트: {', '.join(missing_events)}",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="LOG-001",
            name="로그인 성공/실패 이벤트 기록",
            category="감사로그",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"필수 로그인 이벤트가 모두 기록되고 있습니다. (파일: {log_file})",
            timestamp=datetime.now(),
        )

    def check_required_fields(self) -> TestResult:
        """감사로그에 필수 필드가 포함되어 있는지 확인합니다."""
        log_file = self._find_log_file()

        if not log_file:
            return TestResult(
                id="LOG-002",
                name="감사로그 필수 필드 포함",
                category="감사로그",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="감사로그 파일을 찾을 수 없습니다.",
                timestamp=datetime.now(),
            )

        log_lines = self._read_log_tail(log_file, lines=100)
        sample = "\n".join(log_lines)

        missing_fields = []
        for field_name, pattern in REQUIRED_FIELDS.items():
            if not pattern.search(sample):
                missing_fields.append(field_name)

        if missing_fields:
            return TestResult(
                id="LOG-002",
                name="감사로그 필수 필드 포함",
                category="감사로그",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"감사로그에 누락된 필드: {', '.join(missing_fields)}",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="LOG-002",
            name="감사로그 필수 필드 포함",
            category="감사로그",
            status=TestStatus.PASS,
            engine=self.engine,
            details="감사로그에 필수 필드(타임스탬프, IP주소, 사용자ID)가 모두 포함되어 있습니다.",
            timestamp=datetime.now(),
        )

    def check_no_sensitive_data(self) -> TestResult:
        """감사로그에 민감정보(패스워드 등)가 포함되어 있지 않은지 확인합니다."""
        log_file = self._find_log_file()

        if not log_file:
            return TestResult(
                id="LOG-003",
                name="감사로그 내 민감정보 미포함",
                category="감사로그",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="감사로그 파일을 찾을 수 없습니다.",
                timestamp=datetime.now(),
            )

        log_lines = self._read_log_tail(log_file, lines=200)
        sample = "\n".join(log_lines)

        found_sensitive = []
        for pattern in SENSITIVE_PATTERNS:
            matches = pattern.findall(sample)
            if matches:
                found_sensitive.extend(matches[:2])

        if found_sensitive:
            return TestResult(
                id="LOG-003",
                name="감사로그 내 민감정보 미포함",
                category="감사로그",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"감사로그에 민감정보 패턴 발견: {'; '.join(str(m)[:30] for m in found_sensitive[:3])}",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="LOG-003",
            name="감사로그 내 민감정보 미포함",
            category="감사로그",
            status=TestStatus.PASS,
            engine=self.engine,
            details="감사로그에 민감정보(패스워드, 토큰 등) 미포함 확인.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """감사로그 관련 검사를 모두 실행합니다."""
        return [
            self.check_required_events(),
            self.check_required_fields(),
            self.check_no_sensitive_data(),
        ]
