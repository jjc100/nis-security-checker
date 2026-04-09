"""
체크리스트 엔진 - 항목 로더 모듈
YAML 파일에서 체크리스트 항목을 로드하고 카테고리별로 그룹핑합니다.
"""

from collections import defaultdict
from pathlib import Path

import yaml

from src.models import CheckItem


def load_items(yaml_path: str) -> list[CheckItem]:
    """
    YAML 파일에서 체크리스트 항목을 로드합니다.

    Args:
        yaml_path: YAML 파일 경로

    Returns:
        CheckItem 목록
    """
    with open(yaml_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    items = []
    for raw in data.get("items", []):
        item = CheckItem(
            id=raw["id"],
            category=raw["category"],
            title=raw["title"],
            description=raw["description"],
            method=raw["method"],
            reference=raw.get("reference", ""),
            condition=raw.get("condition"),
        )
        items.append(item)
    return items


def filter_by_method(items: list[CheckItem], method: str) -> list[CheckItem]:
    """
    검사 방법으로 항목을 필터링합니다.

    Args:
        items: 전체 항목 목록
        method: 검사 방법 (blackbox/graybox/checklist)

    Returns:
        필터링된 항목 목록
    """
    return [item for item in items if item.method == method]


def filter_by_features(items: list[CheckItem], features: dict) -> list[CheckItem]:
    """
    기능 플래그에 따라 해당되지 않는 조건부 항목을 제외합니다.

    Args:
        items: 전체 항목 목록
        features: 기능 플래그 딕셔너리

    Returns:
        필터링된 항목 목록
    """
    result = []
    for item in items:
        if item.condition is None:
            result.append(item)
        elif features.get(item.condition, False):
            result.append(item)
    return result


def group_by_category(items: list[CheckItem]) -> dict[str, list[CheckItem]]:
    """
    항목을 카테고리별로 그룹핑합니다.

    Args:
        items: 항목 목록

    Returns:
        카테고리 → 항목 목록 딕셔너리
    """
    groups: dict[str, list[CheckItem]] = defaultdict(list)
    for item in items:
        groups[item.category].append(item)
    return dict(groups)
