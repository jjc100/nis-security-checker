"""
그레이박스 검사 - 메모리 분석 모듈
프로세스 메모리 덤프 후 평문 인증정보를 검색합니다.
"""

import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus

# 평문 인증정보 패턴 (메모리에서 탐지)
CREDENTIAL_PATTERNS = [
    re.compile(rb'password[:=\s]+([^\x00\n\r]{4,64})', re.IGNORECASE),
    re.compile(rb'passwd[:=\s]+([^\x00\n\r]{4,64})', re.IGNORECASE),
    re.compile(rb'Authorization: Basic ([A-Za-z0-9+/=]+)', re.IGNORECASE),
]

# 분석할 프로세스 이름 키워드
TARGET_PROCESS_KEYWORDS = ["nvr", "dvr", "camera", "onvif", "rtsp", "streaming"]

# 메모리 덤프 최대 크기 (16MB)
MAX_DUMP_SIZE = 16 * 1024 * 1024


class MemoryAnalyzer:
    """프로세스 메모리 분석기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"

    def _find_target_pids(self) -> list[int]:
        """분석 대상 프로세스의 PID 목록을 반환합니다."""
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
        /proc/<pid>/mem을 통해 프로세스 메모리를 읽습니다.
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

    def check_plaintext_credentials_in_memory(self) -> TestResult:
        """프로세스 메모리에 평문 인증정보가 존재하는지 확인합니다."""
        # root 권한 확인
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
