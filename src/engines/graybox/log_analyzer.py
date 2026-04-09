"""
그레이박스 검사 - 감사로그 분석 모듈
소스 코드의 로깅 구문에서 민감정보 노출 위험을 탐지하고,
실제 로그 파일에서 필수 이벤트/필드 및 민감정보 포함 여부를 검사합니다.
Windows/.NET/C++ 프로젝트와 Linux 로그 파일을 모두 지원합니다.
"""

import re
from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus
from src.utils.path_validator import is_within_root, DEFAULT_EXCLUDE_DIRS, DEFAULT_MAX_DEPTH

# Linux 폴백 감사로그 파일 경로
LINUX_LOG_PATHS = [
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

# .NET 로깅 구문에서 민감정보 출력 패턴
DOTNET_SENSITIVE_LOG_PATTERNS = [
    # Logger.Log(...password...), Console.WriteLine(...secret...) 등
    re.compile(
        r'(?:Logger|log|Console|Debug|Trace)\s*\.\s*\w+\s*\([^)]*(?:password|secret|token|credential|passwd)[^)]*\)',
        re.IGNORECASE,
    ),
    # string.Format/interpolation에 민감값 포함
    re.compile(
        r'(?:string\.Format|Log\w*)\s*\([^)]*\{[^}]*\}[^)]*\)',
        re.IGNORECASE,
    ),
]

# C++ 로깅 구문에서 민감정보 출력 패턴
CPP_SENSITIVE_LOG_PATTERNS = [
    re.compile(
        r'(?:printf|fprintf|spdlog|LOG_|LOGI|LOGD|LOGE)\s*\([^)]*(?:password|secret|token|credential|passwd)[^)]*\)',
        re.IGNORECASE,
    ),
]

# 소스 파일 확장자
SOURCE_EXTENSIONS = {".cs", ".cpp", ".h", ".c", ".hpp"}

# 제외 디렉터리
EXCLUDED_DIRS = DEFAULT_EXCLUDE_DIRS


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


class LogAnalyzer:
    """감사로그 분석기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"
        self._project_roots = _get_project_roots(config)

    def _find_log_file(self) -> Path | None:
        """존재하는 Linux 로그 파일을 반환합니다."""
        for path_str in LINUX_LOG_PATHS:
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

    def _find_source_files(self, max_count: int = 200) -> list[Path]:
        """분석할 소스 파일 목록을 반환합니다."""
        files: list[Path] = []
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
                files.append(fpath)
                if len(files) >= max_count:
                    return files
        return files

    def _scan_source_for_sensitive_logging(self, source_files: list[Path]) -> list[str]:
        """소스 코드에서 민감정보 로깅 가능성을 탐지합니다."""
        hits: list[str] = []
        for fpath in source_files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                ext = fpath.suffix.lower()

                if ext == ".cs":
                    for pat in DOTNET_SENSITIVE_LOG_PATTERNS:
                        if pat.search(content):
                            hits.append(f"{fpath.name}: .NET 로깅 구문에 민감정보 포함 가능")
                            break
                elif ext in {".cpp", ".h", ".c", ".hpp"}:
                    for pat in CPP_SENSITIVE_LOG_PATTERNS:
                        if pat.search(content):
                            hits.append(f"{fpath.name}: C++ 로깅 구문에 민감정보 포함 가능")
                            break
            except OSError:
                continue
        return hits

    def check_required_events(self) -> TestResult:
        """필수 이벤트(로그인 성공/실패)가 감사로그에 기록되는지 확인합니다."""
        # Windows 프로젝트 모드: 소스 코드에서 로깅 구현 여부 탐지
        source_files = self._find_source_files()
        if source_files:
            # 로그인 이벤트 로깅 구문 존재 여부 확인
            has_login_log = False
            for fpath in source_files:
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore").lower()
                    if re.search(r'(?:log|write|record).*(?:login|logon|auth|signin)', content):
                        has_login_log = True
                        break
                except OSError:
                    continue

            if has_login_log:
                return TestResult(
                    id="LOG-001",
                    name="로그인 성공/실패 이벤트 기록",
                    category="감사로그",
                    status=TestStatus.PASS,
                    engine=self.engine,
                    details=f"{len(source_files)}개 소스 파일 분석 결과: 로그인 이벤트 로깅 구문 탐지됨.",
                    timestamp=datetime.now(),
                )

            return TestResult(
                id="LOG-001",
                name="로그인 성공/실패 이벤트 기록",
                category="감사로그",
                status=TestStatus.MANUAL,
                engine=self.engine,
                details=(
                    f"{len(source_files)}개 소스 파일에서 로그인 이벤트 로깅 구문을 찾지 못했습니다. "
                    "수동 확인이 필요합니다."
                ),
                timestamp=datetime.now(),
            )

        # Linux 폴백: 로그 파일 분석
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
            # Windows 프로젝트 모드: 소스 파일이 있으면 MANUAL
            source_files = self._find_source_files()
            status = TestStatus.MANUAL if source_files else TestStatus.SKIP
            return TestResult(
                id="LOG-002",
                name="감사로그 필수 필드 포함",
                category="감사로그",
                status=status,
                engine=self.engine,
                details="감사로그 파일을 찾을 수 없습니다. 로그 포맷(타임스탬프, IP, 사용자ID)을 수동으로 확인하세요.",
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
        """로그에 민감정보(패스워드 등)가 포함되어 있지 않은지 확인합니다."""
        # Windows 프로젝트 모드: 소스 코드 로깅 구문 분석
        source_files = self._find_source_files()
        if source_files:
            sensitive_hits = self._scan_source_for_sensitive_logging(source_files)
            if sensitive_hits:
                return TestResult(
                    id="LOG-003",
                    name="감사로그 내 민감정보 미포함",
                    category="감사로그",
                    status=TestStatus.FAIL,
                    engine=self.engine,
                    details=f"로깅 구문에 민감정보 포함 위험: {'; '.join(sensitive_hits[:5])}",
                    timestamp=datetime.now(),
                )
            return TestResult(
                id="LOG-003",
                name="감사로그 내 민감정보 미포함",
                category="감사로그",
                status=TestStatus.PASS,
                engine=self.engine,
                details=f"{len(source_files)}개 소스 파일 로깅 구문 분석 완료. 민감정보 로깅 패턴 미탐지.",
                timestamp=datetime.now(),
            )

        # Linux 폴백: 로그 파일 분석
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
