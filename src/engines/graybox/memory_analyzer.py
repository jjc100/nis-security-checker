"""
그레이박스 검사 - 메모리 분석 모듈
Windows 프로젝트 모드: 소스 코드에서 메모리 보안 이슈를 탐지합니다.
Linux 모드: 프로세스 메모리 덤프 후 평문 인증정보를 검색합니다.
"""

import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus

# 평문 인증정보 패턴 (Linux 메모리에서 탐지)
CREDENTIAL_PATTERNS = [
    re.compile(rb'password[:=\s]+([^\x00\n\r]{4,64})', re.IGNORECASE),
    re.compile(rb'passwd[:=\s]+([^\x00\n\r]{4,64})', re.IGNORECASE),
    re.compile(rb'Authorization: Basic ([A-Za-z0-9+/=]+)', re.IGNORECASE),
]

# 분석할 프로세스 이름 키워드 (Linux)
TARGET_PROCESS_KEYWORDS = ["nvr", "dvr", "camera", "onvif", "rtsp", "streaming"]

# 메모리 덤프 최대 크기 (16MB)
MAX_DUMP_SIZE = 16 * 1024 * 1024

# .NET 메모리 보안 이슈 패턴
DOTNET_MEMORY_ISSUE_PATTERNS = [
    # SecureString 대신 일반 string으로 패스워드 저장
    re.compile(r'\bstring\s+\w*(?:password|passwd|secret|credential)\w*\s*=\s*["\']', re.IGNORECASE),
    # 메모리에 패스워드 평문 유지 (GC.Collect 없이)
    re.compile(r'\bstring\s+\w*(?:password|passwd)\w*\s*=\s*\w+\.Password\b', re.IGNORECASE),
    # Marshal.SecureStringToGlobalAllocUnicode 미사용 흔적
    re.compile(r'new\s+NetworkCredential\s*\(\s*\w+\s*,\s*["\']', re.IGNORECASE),
]

# C++ 메모리 보안 이슈 패턴
CPP_MEMORY_ISSUE_PATTERNS = [
    # 패스워드 변수 평문 저장
    re.compile(r'\bchar\s+\w*(?:password|passwd|secret)\w*\s*\[', re.IGNORECASE),
    # memset 없이 패스워드 메모리 해제 의심 패턴
    re.compile(r'free\s*\(\s*\w*(?:password|passwd|secret)\w*\s*\)', re.IGNORECASE),
    # 스택에 패스워드 저장
    re.compile(r'char\s+\w*(?:pwd|pass)\w*\s*\[\d+\]\s*=\s*["\']', re.IGNORECASE),
]

# 소스 파일 확장자
SOURCE_EXTENSIONS = {".cs", ".cpp", ".h", ".c", ".hpp"}

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


class MemoryAnalyzer:
    """프로세스 메모리 / 소스 코드 메모리 보안 분석기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"
        self._project_roots = _get_project_roots(config)

    def _find_target_pids(self) -> list[int]:
        """분석 대상 프로세스의 PID 목록을 반환합니다 (Linux 전용)."""
        pids = []
        try:
            result = subprocess.run(  # noqa: S603
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in result.stdout.splitlines():
                lower_line = line.lower()
                for keyword in TARGET_PROCESS_KEYWORDS:
                    if keyword in lower_line:
                        parts = line.split()
                        if len(parts) > 1:
                            try:
                                pids.append(int(parts[1]))
                            except ValueError:
                                pass
                        break
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return list(set(pids))

    def _read_process_memory(self, pid: int) -> bytes:
        """
        /proc/<pid>/mem을 통해 프로세스 메모리를 읽습니다 (Linux 전용).
        권한이 없으면 빈 바이트를 반환합니다.
        """
        mem_data = b""
        maps_path = Path(f"/proc/{pid}/maps")
        mem_path = Path(f"/proc/{pid}/mem")

        if not maps_path.exists() or not mem_path.exists():
            return mem_data

        try:
            with open(maps_path) as maps_f, open(mem_path, "rb") as mem_f:
                for line in maps_f:
                    parts = line.split()
                    if not parts:
                        continue
                    # 읽기 가능하고 heap/stack 영역만 대상
                    if len(parts) < 2 or "r" not in parts[1]:
                        continue
                    if len(parts) >= 6 and parts[5] not in ("[heap]", "[stack]"):
                        continue

                    start_str, end_str = parts[0].split("-")
                    start = int(start_str, 16)
                    end = int(end_str, 16)
                    size = min(end - start, MAX_DUMP_SIZE - len(mem_data))

                    if size <= 0 or len(mem_data) >= MAX_DUMP_SIZE:
                        break

                    try:
                        mem_f.seek(start)
                        chunk = mem_f.read(size)
                        mem_data += chunk
                    except OSError:
                        continue
        except OSError:
            pass

        return mem_data

    def _find_source_files(self, max_count: int = 200) -> list[Path]:
        """분석할 소스 파일 목록을 반환합니다."""
        files: list[Path] = []
        seen: set[Path] = set()

        for root in self._project_roots:
            if not root.exists():
                continue
            for fpath in root.rglob("*"):
                if _is_excluded(fpath):
                    continue
                if not fpath.is_file():
                    continue
                if fpath.suffix.lower() not in SOURCE_EXTENSIONS:
                    continue
                resolved = fpath.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                files.append(fpath)
                if len(files) >= max_count:
                    return files
        return files

    def _scan_source_for_memory_issues(self, source_files: list[Path]) -> list[str]:
        """소스 코드에서 메모리 보안 이슈 패턴을 탐지합니다."""
        hits: list[str] = []
        for fpath in source_files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                ext = fpath.suffix.lower()

                if ext == ".cs":
                    for pat in DOTNET_MEMORY_ISSUE_PATTERNS:
                        if pat.search(content):
                            hits.append(f"{fpath.name}: .NET 메모리 보안 이슈 패턴")
                            break
                elif ext in {".cpp", ".h", ".c", ".hpp"}:
                    for pat in CPP_MEMORY_ISSUE_PATTERNS:
                        if pat.search(content):
                            hits.append(f"{fpath.name}: C++ 메모리 보안 이슈 패턴")
                            break
            except OSError:
                continue
        return hits

    def check_plaintext_credentials_in_memory(self) -> TestResult:
        """메모리 또는 소스 코드에서 평문 인증정보 보안 이슈를 확인합니다."""
        # Windows 프로젝트 모드: 소스 코드 분석
        source_files = self._find_source_files()
        if source_files:
            issues = self._scan_source_for_memory_issues(source_files)
            if issues:
                return TestResult(
                    id="MEM-001",
                    name="메모리 내 평문 인증정보 미존재",
                    category="메모리보안",
                    status=TestStatus.FAIL,
                    engine=self.engine,
                    details=f"소스 코드에서 메모리 보안 이슈 탐지: {'; '.join(issues[:5])}",
                    timestamp=datetime.now(),
                )
            return TestResult(
                id="MEM-001",
                name="메모리 내 평문 인증정보 미존재",
                category="메모리보안",
                status=TestStatus.PASS,
                engine=self.engine,
                details=f"{len(source_files)}개 소스 파일에서 메모리 보안 이슈 미탐지.",
                timestamp=datetime.now(),
            )

        # 프로젝트 모드(Windows/NVR4)에서 소스 파일이 없으면 SKIP 반환.
        # Linux 런타임 메모리 분석 경로(os.geteuid, /proc, ps 등)로 내려가지 않는다.
        if self._project_roots:
            return TestResult(
                id="MEM-001",
                name="메모리 내 평문 인증정보 미존재",
                category="메모리보안",
                status=TestStatus.SKIP,
                engine=self.engine,
                details=(
                    "분석할 소스 파일을 찾을 수 없습니다. "
                    "config의 project_path 또는 source_paths를 확인하세요."
                ),
                timestamp=datetime.now(),
            )

        # Linux 모드: root 권한 확인
        if os.geteuid() != 0:
            return TestResult(
                id="MEM-001",
                name="메모리 내 평문 인증정보 미존재",
                category="메모리보안",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="메모리 분석은 root 권한이 필요합니다. 권한 상승 후 재실행하세요.",
                timestamp=datetime.now(),
            )

        pids = self._find_target_pids()

        if not pids:
            return TestResult(
                id="MEM-001",
                name="메모리 내 평문 인증정보 미존재",
                category="메모리보안",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="분석 대상 프로세스를 찾을 수 없습니다.",
                timestamp=datetime.now(),
            )

        found_creds = []
        for pid in pids[:3]:  # 최대 3개 프로세스만 분석
            mem_data = self._read_process_memory(pid)
            if not mem_data:
                continue
            for pattern in CREDENTIAL_PATTERNS:
                matches = pattern.findall(mem_data)
                if matches:
                    found_creds.append(f"PID {pid}: 인증정보 패턴 {len(matches)}건 탐지")

        if found_creds:
            return TestResult(
                id="MEM-001",
                name="메모리 내 평문 인증정보 미존재",
                category="메모리보안",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"메모리에서 평문 인증정보 탐지: {'; '.join(found_creds)}",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="MEM-001",
            name="메모리 내 평문 인증정보 미존재",
            category="메모리보안",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"{len(pids)}개 프로세스 메모리에서 평문 인증정보 미탐지.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """메모리 관련 검사를 모두 실행합니다."""
        return [self.check_plaintext_credentials_in_memory()]
