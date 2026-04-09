"""
경로 입력 검증 및 안전화 유틸리티

경로 traversal 방지, 스캔 범위 제한, 파일명 안전화 기능을 제공합니다.
graybox 분석기와 체크리스트 엔진 전반에서 공통으로 사용합니다.
"""

import re
from pathlib import Path

# 공통 제외 디렉터리 목록
DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", ".vs", ".idea", "obj", ".svn", "__pycache__",
})

# 기본 스캔 제한값
DEFAULT_MAX_FILES: int = 100_000
DEFAULT_MAX_DEPTH: int = 20


def validate_directory(path: "str | Path", name: str = "경로") -> Path:
    """
    경로가 빈값이 아니고, 존재하며, 디렉터리인지 검증합니다.

    Args:
        path: 검증할 경로
        name: 오류 메시지에 사용할 경로 이름

    Returns:
        검증된 Path 객체

    Raises:
        ValueError: 빈값이거나 디렉터리가 아닌 경우
        FileNotFoundError: 경로가 존재하지 않는 경우
    """
    if not path or (isinstance(path, str) and not path.strip()):
        raise ValueError(f"{name}이(가) 비어 있습니다.")

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{name}을(를) 찾을 수 없습니다: {path}")
    if not p.is_dir():
        raise ValueError(f"{name}이(가) 디렉터리가 아닙니다: {path}")

    return p


def validate_file(path: "str | Path", name: str = "파일") -> Path:
    """
    경로가 빈값이 아니고, 존재하며, 파일인지 검증합니다.

    Args:
        path: 검증할 경로
        name: 오류 메시지에 사용할 경로 이름

    Returns:
        검증된 Path 객체

    Raises:
        ValueError: 빈값이거나 파일이 아닌 경우
        FileNotFoundError: 경로가 존재하지 않는 경우
    """
    if not path or (isinstance(path, str) and not path.strip()):
        raise ValueError(f"{name}이(가) 비어 있습니다.")

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{name}을(를) 찾을 수 없습니다: {path}")
    if not p.is_file():
        raise ValueError(f"{name}이(가) 파일이 아닙니다: {path}")

    return p


def resolve_and_normalize(path: "str | Path") -> Path:
    """
    경로를 절대 경로로 정규화합니다 (심볼릭 링크 해소 포함).

    Args:
        path: 정규화할 경로

    Returns:
        정규화된 절대 Path 객체
    """
    return Path(path).resolve()


def is_within_root(path: "str | Path", root: "str | Path") -> bool:
    """
    경로가 루트 디렉터리 내부에 있는지 확인합니다.
    심볼릭 링크 해소 후 비교하여 우회 경로를 방지합니다.

    Args:
        path: 확인할 경로
        root: 루트 디렉터리 경로

    Returns:
        경로가 루트 내부에 있으면 True, 아니면 False
    """
    try:
        resolved_path = Path(path).resolve()
        resolved_root = Path(root).resolve()
        resolved_path.relative_to(resolved_root)
        return True
    except ValueError:
        return False


def sanitize_filename(name: str) -> str:
    """
    파일명을 안전하게 만듭니다 (경로 traversal 방지).
    영숫자, 하이픈, 언더스코어, 점만 허용합니다.

    Args:
        name: 안전화할 파일명

    Returns:
        안전화된 파일명

    Raises:
        ValueError: 빈값이거나 안전화 후 빈 문자열이 되는 경우
    """
    if not name or not name.strip():
        raise ValueError("파일명이 비어 있습니다.")

    # 영숫자, 하이픈, 언더스코어, 점만 허용 (나머지는 언더스코어로 치환)
    safe = re.sub(r"[^\w\-.]", "_", name)
    # 경로 구분자 방지: 슬래시, 백슬래시 등은 이미 위에서 처리됨
    # 앞뒤 점 제거 (숨김 파일·디렉터리 패턴 방지)
    safe = safe.strip(".")

    if not safe:
        raise ValueError(f"파일명이 안전화 후 비어 있습니다: {name!r}")

    return safe
