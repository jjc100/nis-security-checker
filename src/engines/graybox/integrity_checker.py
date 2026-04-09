"""
그레이박스 검사 - 파일 무결성 검사 모듈
주요 파일의 SHA-256 해시를 계산하고 기준값과 비교합니다.
Windows 프로젝트의 빌드 산출물(.exe, .dll, .config)도 지원합니다.
"""

from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus
from src.utils.crypto import sha256_file

# 무결성 검사 대상 빌드 산출물 확장자
BUILD_OUTPUT_EXTENSIONS = {".exe", ".dll", ".config", ".lib"}

# 제외 디렉터리
EXCLUDED_DIRS = {".git", "node_modules", ".vs", ".idea", "obj"}


def _is_excluded(path: Path) -> bool:
    """제외 디렉터리 여부를 확인합니다."""
    return any(part in EXCLUDED_DIRS for part in path.parts)


class IntegrityChecker:
    """파일 무결성 검사기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"
        self.baseline: dict[str, str] = config.get("integrity_baseline", {})

    def _find_build_outputs(self, max_count: int = 50) -> list[Path]:
        """
        빌드 산출물 파일 목록을 반환합니다.
        project_path 또는 build_output_path가 설정된 경우 해당 경로를 탐색합니다.
        """
        target = self.config.get("target", {})
        roots: list[Path] = []

        build_output = target.get("build_output_path")
        if build_output:
            p = Path(build_output)
            if p.exists():
                roots.append(p)

        project_path = target.get("project_path")
        if project_path:
            p = Path(project_path)
            if p.exists():
                roots.append(p)

        files: list[Path] = []
        seen: set[Path] = set()

        for root in roots:
            for fpath in root.rglob("*"):
                if _is_excluded(fpath):
                    continue
                if not fpath.is_file():
                    continue
                if fpath.suffix.lower() not in BUILD_OUTPUT_EXTENSIONS:
                    continue
                resolved = fpath.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                files.append(fpath)
                if len(files) >= max_count:
                    return files
        return files

    def check_file_integrity(self) -> TestResult:
        """
        설정된 기준 해시값과 현재 파일 해시를 비교합니다.

        기준값이 비어 있으면 현재 해시를 기록하는 MANUAL 결과를 반환합니다.
        기준값이 없고 Windows 프로젝트 경로가 있으면 산출물 목록을 제공합니다.
        """
        if not self.baseline:
            # Windows 프로젝트 빌드 산출물 목록 제공
            build_files = self._find_build_outputs()
            if build_files:
                file_list = "\n".join(f"  {f}" for f in build_files[:10])
                return TestResult(
                    id="SW-003",
                    name="파일 무결성 검증",
                    category="소프트웨어보안",
                    status=TestStatus.MANUAL,
                    engine=self.engine,
                    details=(
                        f"무결성 기준 해시가 설정되지 않았습니다. "
                        f"아래 산출물을 integrity_baseline에 등록하세요:\n{file_list}"
                    ),
                    timestamp=datetime.now(),
                )

            return TestResult(
                id="SW-003",
                name="파일 무결성 검증",
                category="소프트웨어보안",
                status=TestStatus.SKIP,
                engine=self.engine,
                details=(
                    "무결성 기준 해시가 설정되지 않았습니다. "
                    "config/target_config.yaml의 integrity_baseline을 설정하세요."
                ),
                timestamp=datetime.now(),
            )

        tampered = []
        missing = []
        current_hashes = {}

        for filepath, expected_hash in self.baseline.items():
            path = Path(filepath)
            if not path.exists():
                missing.append(filepath)
                continue
            try:
                actual_hash = sha256_file(path)
                current_hashes[filepath] = actual_hash

                if expected_hash and actual_hash != expected_hash:
                    tampered.append(
                        f"{filepath}: 예상={expected_hash[:16]}..., 실제={actual_hash[:16]}..."
                    )
            except OSError as e:
                missing.append(f"{filepath} (오류: {e})")

        if tampered:
            return TestResult(
                id="SW-003",
                name="파일 무결성 검증",
                category="소프트웨어보안",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"무결성 검증 실패: {'; '.join(tampered)}",
                timestamp=datetime.now(),
            )

        if missing:
            return TestResult(
                id="SW-003",
                name="파일 무결성 검증",
                category="소프트웨어보안",
                status=TestStatus.MANUAL,
                engine=self.engine,
                details=f"파일을 찾을 수 없거나 읽을 수 없음: {', '.join(missing)}",
                timestamp=datetime.now(),
            )

        # 기준값이 비어 있는 항목이 있으면 MANUAL (초기 기준값 설정 필요)
        empty_baselines = [fp for fp, h in self.baseline.items() if not h]
        if empty_baselines:
            hash_report = "\n".join(
                f"  {fp}: {current_hashes.get(fp, '읽기 불가')}"
                for fp in empty_baselines
            )
            return TestResult(
                id="SW-003",
                name="파일 무결성 검증",
                category="소프트웨어보안",
                status=TestStatus.MANUAL,
                engine=self.engine,
                details=f"기준 해시가 없는 파일의 현재 해시:\n{hash_report}\n위 해시값을 integrity_baseline에 설정하세요.",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="SW-003",
            name="파일 무결성 검증",
            category="소프트웨어보안",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"{len(self.baseline)}개 파일 무결성 검증 완료.",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """무결성 검사를 실행합니다."""
        return [self.check_file_integrity()]
