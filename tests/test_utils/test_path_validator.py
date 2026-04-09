"""
경로 입력 검증 유틸리티 단위 테스트
path_validator.py의 모든 함수를 검증합니다.
"""

import pytest
from pathlib import Path

from src.utils.path_validator import (
    validate_directory,
    validate_file,
    resolve_and_normalize,
    is_within_root,
    sanitize_filename,
    DEFAULT_EXCLUDE_DIRS,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_DEPTH,
)


# ────────────────────────────────────────────────────────────────────────────────
# validate_directory 테스트
# ────────────────────────────────────────────────────────────────────────────────

class TestValidateDirectory:
    """validate_directory 함수 테스트"""

    def test_valid_directory_returns_path(self, tmp_path):
        """존재하는 디렉터리는 Path 객체를 반환해야 한다."""
        result = validate_directory(tmp_path)
        assert isinstance(result, Path)
        assert result == tmp_path

    def test_valid_directory_str_path(self, tmp_path):
        """문자열 경로도 처리되어야 한다."""
        result = validate_directory(str(tmp_path))
        assert isinstance(result, Path)

    def test_empty_string_raises_value_error(self):
        """빈 문자열은 ValueError를 발생시켜야 한다."""
        with pytest.raises(ValueError, match="비어 있습니다"):
            validate_directory("")

    def test_whitespace_only_raises_value_error(self):
        """공백만 있는 문자열은 ValueError를 발생시켜야 한다."""
        with pytest.raises(ValueError, match="비어 있습니다"):
            validate_directory("   ")

    def test_nonexistent_path_raises_file_not_found(self, tmp_path):
        """존재하지 않는 경로는 FileNotFoundError를 발생시켜야 한다."""
        missing = tmp_path / "nonexistent_dir"
        with pytest.raises(FileNotFoundError, match="찾을 수 없습니다"):
            validate_directory(missing)

    def test_file_path_raises_value_error(self, tmp_path):
        """파일 경로를 디렉터리로 검증하면 ValueError를 발생시켜야 한다."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("내용", encoding="utf-8")
        with pytest.raises(ValueError, match="디렉터리가 아닙니다"):
            validate_directory(test_file)

    def test_custom_name_in_error_message(self, tmp_path):
        """오류 메시지에 사용자 정의 이름이 포함되어야 한다."""
        missing = tmp_path / "nonexistent"
        with pytest.raises(FileNotFoundError, match="프로젝트 경로"):
            validate_directory(missing, name="프로젝트 경로")


# ────────────────────────────────────────────────────────────────────────────────
# validate_file 테스트
# ────────────────────────────────────────────────────────────────────────────────

class TestValidateFile:
    """validate_file 함수 테스트"""

    def test_valid_file_returns_path(self, tmp_path):
        """존재하는 파일은 Path 객체를 반환해야 한다."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("내용", encoding="utf-8")
        result = validate_file(test_file)
        assert isinstance(result, Path)
        assert result == test_file

    def test_empty_string_raises_value_error(self):
        """빈 문자열은 ValueError를 발생시켜야 한다."""
        with pytest.raises(ValueError, match="비어 있습니다"):
            validate_file("")

    def test_nonexistent_file_raises_file_not_found(self, tmp_path):
        """존재하지 않는 파일은 FileNotFoundError를 발생시켜야 한다."""
        missing = tmp_path / "nonexistent.txt"
        with pytest.raises(FileNotFoundError, match="찾을 수 없습니다"):
            validate_file(missing)

    def test_directory_raises_value_error(self, tmp_path):
        """디렉터리 경로를 파일로 검증하면 ValueError를 발생시켜야 한다."""
        with pytest.raises(ValueError, match="파일이 아닙니다"):
            validate_file(tmp_path)

    def test_custom_name_in_error_message(self, tmp_path):
        """오류 메시지에 사용자 정의 이름이 포함되어야 한다."""
        missing = tmp_path / "missing.txt"
        with pytest.raises(FileNotFoundError, match="증빙 파일"):
            validate_file(missing, name="증빙 파일")


# ────────────────────────────────────────────────────────────────────────────────
# resolve_and_normalize 테스트
# ────────────────────────────────────────────────────────────────────────────────

class TestResolveAndNormalize:
    """resolve_and_normalize 함수 테스트"""

    def test_absolute_path_returned(self, tmp_path):
        """절대 경로가 반환되어야 한다."""
        result = resolve_and_normalize(tmp_path)
        assert result.is_absolute()

    def test_relative_path_resolved(self, tmp_path, monkeypatch):
        """상대 경로가 절대 경로로 변환되어야 한다."""
        monkeypatch.chdir(tmp_path)
        result = resolve_and_normalize(".")
        assert result.is_absolute()

    def test_string_input_accepted(self, tmp_path):
        """문자열 입력도 처리되어야 한다."""
        result = resolve_and_normalize(str(tmp_path))
        assert isinstance(result, Path)


# ────────────────────────────────────────────────────────────────────────────────
# is_within_root 테스트
# ────────────────────────────────────────────────────────────────────────────────

class TestIsWithinRoot:
    """is_within_root 함수 테스트"""

    def test_child_path_returns_true(self, tmp_path):
        """루트 내부 경로는 True를 반환해야 한다."""
        child = tmp_path / "subdir" / "file.txt"
        assert is_within_root(child, tmp_path) is True

    def test_root_itself_returns_true(self, tmp_path):
        """루트 자체는 True를 반환해야 한다."""
        assert is_within_root(tmp_path, tmp_path) is True

    def test_parent_path_returns_false(self, tmp_path):
        """루트의 부모 경로는 False를 반환해야 한다."""
        assert is_within_root(tmp_path.parent, tmp_path) is False

    def test_sibling_path_returns_false(self, tmp_path):
        """루트 외부 경로는 False를 반환해야 한다."""
        root = tmp_path / "project"
        outside = tmp_path / "other_project"
        assert is_within_root(outside, root) is False

    def test_symlink_outside_root_returns_false(self, tmp_path):
        """루트 밖을 가리키는 심볼릭 링크는 False를 반환해야 한다."""
        root = tmp_path / "project"
        root.mkdir()
        outside = tmp_path / "secret"
        outside.mkdir()

        symlink = root / "link_to_outside"
        try:
            symlink.symlink_to(outside)
            # 심볼릭 링크가 실제로 가리키는 경로(resolved)가 root 바깥이어야 함
            assert is_within_root(symlink.resolve(), root) is False
        except (OSError, NotImplementedError):
            # 심볼릭 링크를 지원하지 않는 환경에서는 건너뜀
            pytest.skip("심볼릭 링크를 지원하지 않는 환경입니다.")

    def test_path_traversal_outside_root_returns_false(self, tmp_path):
        """경로 traversal 시도는 False를 반환해야 한다."""
        root = tmp_path / "project"
        # root/../other 같은 경로
        traversal = tmp_path / "other"
        assert is_within_root(traversal, root) is False

    def test_string_inputs_accepted(self, tmp_path):
        """문자열 입력도 처리되어야 한다."""
        child = str(tmp_path / "file.txt")
        root = str(tmp_path)
        assert is_within_root(child, root) is True


# ────────────────────────────────────────────────────────────────────────────────
# sanitize_filename 테스트
# ────────────────────────────────────────────────────────────────────────────────

class TestSanitizeFilename:
    """sanitize_filename 함수 테스트"""

    def test_alphanumeric_unchanged(self):
        """영숫자는 변경 없이 반환되어야 한다."""
        assert sanitize_filename("abc123") == "abc123"

    def test_hyphen_and_underscore_preserved(self):
        """하이픈과 언더스코어는 유지되어야 한다."""
        result = sanitize_filename("AUTH-001_test")
        assert result == "AUTH-001_test"

    def test_slash_replaced(self):
        """슬래시는 언더스코어로 치환되어야 한다."""
        result = sanitize_filename("path/to/file")
        assert "/" not in result

    def test_backslash_replaced(self):
        """백슬래시는 언더스코어로 치환되어야 한다."""
        result = sanitize_filename("path\\to\\file")
        assert "\\" not in result

    def test_dotdot_traversal_sanitized(self):
        """.. 경로 traversal 시도는 경로 구분자가 제거되어 안전화되어야 한다."""
        result = sanitize_filename("../../../etc/passwd")
        # 핵심 보안 속성: 경로 구분자(슬래시)가 제거되어야 함
        assert "/" not in result
        assert "\\" not in result
        # 결과는 단일 파일명 문자열이어야 함 (비어 있지 않아야 함)
        assert len(result) > 0
        # 슬래시가 언더스코어로 치환되어 단일 파일명이 됨
        assert result == "_.._.._etc_passwd"

    def test_leading_dot_removed(self):
        """앞에 오는 점은 제거되어야 한다."""
        result = sanitize_filename(".hidden")
        assert not result.startswith(".")

    def test_empty_string_raises_value_error(self):
        """빈 문자열은 ValueError를 발생시켜야 한다."""
        with pytest.raises(ValueError, match="비어 있습니다"):
            sanitize_filename("")

    def test_only_special_chars_raises_value_error(self):
        """안전화 후 빈 문자열이 되면 ValueError를 발생시켜야 한다."""
        with pytest.raises(ValueError):
            sanitize_filename("...")

    def test_space_replaced(self):
        """공백은 언더스코어로 치환되어야 한다."""
        result = sanitize_filename("my file name")
        assert " " not in result

    def test_item_id_sanitized(self):
        """일반적인 체크리스트 항목 ID는 안전화 후 동일해야 한다."""
        result = sanitize_filename("AUTH-001")
        assert result == "AUTH-001"


# ────────────────────────────────────────────────────────────────────────────────
# DEFAULT_EXCLUDE_DIRS / DEFAULT_MAX_FILES / DEFAULT_MAX_DEPTH 상수 테스트
# ────────────────────────────────────────────────────────────────────────────────

class TestConstants:
    """모듈 상수 테스트"""

    def test_default_exclude_dirs_contains_git(self):
        """.git은 제외 디렉터리에 포함되어야 한다."""
        assert ".git" in DEFAULT_EXCLUDE_DIRS

    def test_default_exclude_dirs_contains_node_modules(self):
        """node_modules는 제외 디렉터리에 포함되어야 한다."""
        assert "node_modules" in DEFAULT_EXCLUDE_DIRS

    def test_default_max_files_reasonable(self):
        """기본 최대 파일 수는 양수이어야 한다."""
        assert DEFAULT_MAX_FILES > 0

    def test_default_max_depth_reasonable(self):
        """기본 최대 깊이는 양수이어야 한다."""
        assert DEFAULT_MAX_DEPTH > 0
