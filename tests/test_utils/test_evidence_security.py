"""
EvidenceManager 보안 기능 단위 테스트
attach()의 입력 검증, 파일명 안전화, 경로 traversal 방지를 검증합니다.
"""

import pytest
from pathlib import Path

from src.engines.checklist.evidence import EvidenceManager


class TestEvidenceManagerSecurity:
    """EvidenceManager 보안 관련 테스트"""

    def test_attach_valid_file_succeeds(self, tmp_path):
        """유효한 파일을 첨부하면 저장 경로를 반환해야 한다."""
        evidence_dir = tmp_path / "evidence"
        src_file = tmp_path / "report.txt"
        src_file.write_text("증빙 내용", encoding="utf-8")

        mgr = EvidenceManager(str(evidence_dir))
        result = mgr.attach("AUTH-001", str(src_file))

        assert Path(result).exists()
        assert "AUTH-001" in Path(result).name

    def test_attach_empty_item_id_raises(self, tmp_path):
        """item_id가 빈 문자열이면 ValueError를 발생시켜야 한다."""
        evidence_dir = tmp_path / "evidence"
        src_file = tmp_path / "file.txt"
        src_file.write_text("내용", encoding="utf-8")

        mgr = EvidenceManager(str(evidence_dir))
        with pytest.raises(ValueError):
            mgr.attach("", str(src_file))

    def test_attach_nonexistent_source_raises(self, tmp_path):
        """존재하지 않는 source_path는 FileNotFoundError를 발생시켜야 한다."""
        evidence_dir = tmp_path / "evidence"
        missing = tmp_path / "nonexistent.txt"

        mgr = EvidenceManager(str(evidence_dir))
        with pytest.raises(FileNotFoundError):
            mgr.attach("AUTH-001", str(missing))

    def test_attach_directory_as_source_raises(self, tmp_path):
        """디렉터리를 source_path로 지정하면 ValueError를 발생시켜야 한다."""
        evidence_dir = tmp_path / "evidence"
        src_dir = tmp_path / "subdir"
        src_dir.mkdir()

        mgr = EvidenceManager(str(evidence_dir))
        with pytest.raises(ValueError):
            mgr.attach("AUTH-001", str(src_dir))

    def test_attach_special_char_item_id_sanitized(self, tmp_path):
        """특수 문자가 포함된 item_id는 안전화된 파일명으로 저장되어야 한다."""
        evidence_dir = tmp_path / "evidence"
        src_file = tmp_path / "file.txt"
        src_file.write_text("내용", encoding="utf-8")

        mgr = EvidenceManager(str(evidence_dir))
        # 슬래시가 포함된 item_id (경로 traversal 시도)
        result = mgr.attach("AUTH/001", str(src_file))

        # 파일이 evidence_dir 내부에 있어야 함
        result_path = Path(result)
        assert str(result_path).startswith(str(evidence_dir.resolve()))
        # 파일명에 슬래시가 없어야 함
        assert "/" not in result_path.name
        # 슬래시가 언더스코어로 치환된 item_id 부분이 파일명에 있어야 함
        assert "AUTH_001" in result_path.name

    def test_registry_recorded_after_attach(self, tmp_path):
        """attach 성공 후 레지스트리에 항목이 기록되어야 한다."""
        evidence_dir = tmp_path / "evidence"
        src_file = tmp_path / "file.txt"
        src_file.write_text("내용", encoding="utf-8")

        mgr = EvidenceManager(str(evidence_dir))
        mgr.attach("AUTH-001", str(src_file))

        info = mgr.get_evidence("AUTH-001")
        assert info is not None
        assert "sha256" in info
        assert "stored" in info

    def test_verify_returns_true_for_intact_file(self, tmp_path):
        """무결성이 보존된 파일은 verify가 True를 반환해야 한다."""
        evidence_dir = tmp_path / "evidence"
        src_file = tmp_path / "file.txt"
        src_file.write_text("내용", encoding="utf-8")

        mgr = EvidenceManager(str(evidence_dir))
        mgr.attach("AUTH-001", str(src_file))

        assert mgr.verify("AUTH-001") is True

    def test_verify_returns_false_for_missing_item(self, tmp_path):
        """등록되지 않은 항목은 verify가 False를 반환해야 한다."""
        evidence_dir = tmp_path / "evidence"
        mgr = EvidenceManager(str(evidence_dir))
        assert mgr.verify("NONEXISTENT") is False
