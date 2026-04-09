"""
체크리스트 엔진 - 증빙 파일 관리 모듈
증빙 파일을 지정 디렉토리에 저장하고 해시를 기록합니다.
"""

import shutil
from datetime import datetime
from pathlib import Path

from src.utils.crypto import sha256_file


class EvidenceManager:
    """증빙 파일 관리자"""

    def __init__(self, evidence_dir: str = "output/evidence") -> None:
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.registry: dict[str, dict] = {}  # item_id → 증빙 정보

    def attach(self, item_id: str, source_path: str) -> str:
        """
        증빙 파일을 저장하고 SHA-256 해시를 기록합니다.

        Args:
            item_id: 체크리스트 항목 ID
            source_path: 원본 파일 경로

        Returns:
            저장된 파일 경로
        """
        src = Path(source_path)
        if not src.exists():
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {source_path}")

        # 파일명: {item_id}_{타임스탬프}_{원본파일명}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest_name = f"{item_id}_{timestamp}_{src.name}"
        dest = self.evidence_dir / dest_name

        shutil.copy2(src, dest)
        file_hash = sha256_file(dest)

        self.registry[item_id] = {
            "original": str(src),
            "stored": str(dest),
            "sha256": file_hash,
            "timestamp": datetime.now().isoformat(),
        }

        return str(dest)

    def get_evidence(self, item_id: str) -> dict | None:
        """
        항목 ID에 대한 증빙 정보를 반환합니다.

        Args:
            item_id: 체크리스트 항목 ID

        Returns:
            증빙 정보 딕셔너리 또는 None
        """
        return self.registry.get(item_id)

    def list_all(self) -> dict[str, dict]:
        """모든 증빙 파일 정보를 반환합니다."""
        return dict(self.registry)

    def verify(self, item_id: str) -> bool:
        """
        저장된 증빙 파일의 무결성을 검증합니다.

        Args:
            item_id: 체크리스트 항목 ID

        Returns:
            무결성 검증 통과 여부
        """
        info = self.registry.get(item_id)
        if not info:
            return False

        stored_path = Path(info["stored"])
        if not stored_path.exists():
            return False

        current_hash = sha256_file(stored_path)
        return current_hash == info["sha256"]
