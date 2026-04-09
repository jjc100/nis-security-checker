"""
리포트 - 결과 통합 생성기 모듈
3개 엔진의 결과를 통합하고 통계를 생성합니다.
"""

from collections import defaultdict
from datetime import datetime

from src.models import TestResult, TestStatus


class ReportGenerator:
    """검사 결과 리포트 생성기"""

    def __init__(self, results: list[TestResult], config: dict) -> None:
        self.results = results
        self.config = config

    def _calculate_stats(self) -> dict:
        """전체 결과 통계를 계산합니다."""
        total = len(self.results)
        status_counts: dict[str, int] = defaultdict(int)
        engine_counts: dict[str, int] = defaultdict(int)
        category_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for r in self.results:
            status_counts[r.status.value] += 1
            engine_counts[r.engine] += 1
            category_counts[r.category][r.status.value] += 1

        pass_rate = (
            round(status_counts.get("PASS", 0) / total * 100, 1)
            if total > 0
            else 0.0
        )

        return {
            "total": total,
            "pass": status_counts.get("PASS", 0),
            "fail": status_counts.get("FAIL", 0),
            "skip": status_counts.get("SKIP", 0),
            "manual": status_counts.get("MANUAL", 0),
            "error": status_counts.get("ERROR", 0),
            "pass_rate": pass_rate,
            "by_engine": dict(engine_counts),
            "by_category": {cat: dict(counts) for cat, counts in category_counts.items()},
        }

    def _group_by_category(self) -> dict[str, list[dict]]:
        """결과를 카테고리별로 그룹핑합니다."""
        groups: dict[str, list[dict]] = defaultdict(list)
        for r in self.results:
            groups[r.category].append(r.to_dict())
        return dict(groups)

    def generate(self) -> dict:
        """
        리포트 데이터를 생성합니다.

        Returns:
            리포트 딕셔너리 (템플릿/JSON 포맷터에서 사용)
        """
        stats = self._calculate_stats()
        by_category = self._group_by_category()

        target = self.config.get("target", {})

        return {
            "meta": {
                "title": "영상보안제품 보안요구사항 적합성 검사 결과",
                "generated_at": datetime.now().isoformat(),
                "target_host": target.get("host", "N/A"),
                "version": "1.0.0",
            },
            "summary": stats,
            "by_category": by_category,
            "results": [r.to_dict() for r in self.results],
        }
