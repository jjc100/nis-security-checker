"""
그레이박스 검사 - 영상 I-frame 암호화 확인 모듈
영상 파일의 I-frame(키프레임)에 암호화가 적용되어 있는지 엔트로피 분석으로 확인합니다.
"""

from datetime import datetime
from pathlib import Path

from src.models import TestResult, TestStatus
from src.utils.crypto import calculate_entropy

# 영상 파일 확장자
VIDEO_EXTENSIONS = {".mp4", ".avi", ".mkv", ".ts", ".h264", ".h265", ".264", ".265"}

# 영상 검색 경로
VIDEO_PATHS = ["/var/recordings", "/opt/recordings", "/data/videos", "/media"]

# I-frame 시그니처 (H.264/H.265)
H264_IFRAME_MARKERS = [b"\x00\x00\x00\x01\x65", b"\x00\x00\x01\x65"]  # IDR slice
H265_IFRAME_MARKERS = [b"\x00\x00\x00\x01\x26", b"\x00\x00\x01\x26"]  # IDR_W_RADL

# 암호화된 데이터의 최소 엔트로피 임계값
ENCRYPTION_ENTROPY_THRESHOLD = 7.2

# 분석할 최대 바이트 수 (4MB)
MAX_ANALYZE_BYTES = 4 * 1024 * 1024


class IFrameChecker:
    """영상 I-frame 암호화 확인기"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"

    def _find_video_files(self, max_count: int = 5) -> list[Path]:
        """영상 파일을 탐색합니다."""
        videos = []
        for dir_str in VIDEO_PATHS:
            path = Path(dir_str)
            if not path.exists():
                continue
            for ext in VIDEO_EXTENSIONS:
                for vpath in path.rglob(f"*{ext}"):
                    if vpath.is_file():
                        videos.append(vpath)
                        if len(videos) >= max_count:
                            return videos
        return videos

    def _analyze_iframe_encryption(self, video_path: Path) -> bool:
        """
        영상 파일에서 I-frame 데이터의 엔트로피를 분석합니다.
        엔트로피가 높으면 암호화되어 있을 가능성이 높습니다.

        Returns:
            암호화 여부 추정
        """
        try:
            with open(video_path, "rb") as f:
                data = f.read(MAX_ANALYZE_BYTES)

            # I-frame 마커 탐색
            for marker in H264_IFRAME_MARKERS + H265_IFRAME_MARKERS:
                idx = data.find(marker)
                if idx >= 0:
                    # I-frame 이후 4KB 데이터의 엔트로피 계산
                    iframe_data = data[idx : idx + 4096]
                    entropy = calculate_entropy(iframe_data)
                    return entropy >= ENCRYPTION_ENTROPY_THRESHOLD

            # I-frame 마커가 없으면 전체 엔트로피로 판단
            entropy = calculate_entropy(data[:4096])
            return entropy >= ENCRYPTION_ENTROPY_THRESHOLD

        except OSError:
            return False

    def check_iframe_encryption(self) -> TestResult:
        """영상 파일의 I-frame 암호화 여부를 확인합니다."""
        video_files = self._find_video_files()

        if not video_files:
            return TestResult(
                id="VIDEO-001",
                name="영상 I-frame 암호화",
                category="영상보안",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="분석할 영상 파일을 찾을 수 없습니다. 접근 권한이 필요하거나 경로가 다를 수 있습니다.",
                timestamp=datetime.now(),
            )

        encrypted_count = 0
        unencrypted = []

        for vpath in video_files:
            if self._analyze_iframe_encryption(vpath):
                encrypted_count += 1
            else:
                unencrypted.append(vpath.name)

        if not unencrypted:
            return TestResult(
                id="VIDEO-001",
                name="영상 I-frame 암호화",
                category="영상보안",
                status=TestStatus.PASS,
                engine=self.engine,
                details=f"{len(video_files)}개 영상 파일 모두 I-frame 암호화 적용됨 (엔트로피 분석 기준).",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="VIDEO-001",
            name="영상 I-frame 암호화",
            category="영상보안",
            status=TestStatus.FAIL,
            engine=self.engine,
            details=f"I-frame 암호화 미적용 의심 파일: {', '.join(unencrypted)}",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """I-frame 암호화 관련 검사를 모두 실행합니다."""
        return [self.check_iframe_encryption()]
