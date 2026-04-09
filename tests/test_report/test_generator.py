"""
리포트 생성기 단위 테스트
"""

from datetime import datetime

import pytest

from src.models import TestResult, TestStatus
from src.report.generator import ReportGenerator


@pytest.fixture
def sample_results():
    """테스트용 검사 결과 픽스처"""
    return [
        TestResult(
            id="CRYPT-001", name="TLS 1.2 이상 사용 확인", category="암호화",
            status=TestStatus.PASS, engine="blackbox",
            details="TLSv1.3 협상됨", timestamp=datetime.now(),
        ),
        TestResult(
            id="AUTH-003", name="로그인 5회 실패 시 잠금", category="인증",
            status=TestStatus.FAIL, engine="blackbox",
            details="잠금 미적용", timestamp=datetime.now(),
        ),
        TestResult(
            id="AUTH-008", name="RTSP 인증 필수 적용", category="인증",
            status=TestStatus.SKIP, engine="blackbox",
            details="RTSP 비활성화", timestamp=datetime.now(),
        ),
        TestResult(
            id="FS-002", name="평문 패스워드 설정 파일 저장 금지", category="파일시스템",
            status=TestStatus.PASS, engine="graybox",
            details="평문 패스워드 미탐지", timestamp=datetime.now(),
        ),
        TestResult(
            id="AUTH-001", name="기본 계정 변경 강제", category="인증",
            status=TestStatus.MANUAL, engine="checklist",
            details="수동 확인 필요", timestamp=datetime.now(),
        ),
    ]


@pytest.fixture
def generator(sample_results, sample_config):
    return ReportGenerator(results=sample_results, config=sample_config)


class TestReportGenerator:
    """ReportGenerator 테스트"""

    def test_generate_returns_dict(self, generator):
        """generate()는 딕셔너리를 반환해야 한다."""
        report = generator.generate()
        assert isinstance(report, dict)

    def test_report_has_required_keys(self, generator):
        """리포트에 meta, summary, by_category, results 키가 있어야 한다."""
        report = generator.generate()
        assert "meta" in report
        assert "summary" in report
        assert "by_category" in report
        assert "results" in report

    def test_summary_counts(self, generator):
        """통계 카운트가 올바르게 계산되어야 한다."""
        report = generator.generate()
        summary = report["summary"]
        assert summary["total"] == 5
        assert summary["pass"] == 2
        assert summary["fail"] == 1
        assert summary["skip"] == 1
        assert summary["manual"] == 1
        assert summary["error"] == 0

    def test_pass_rate_calculation(self, generator):
        """통과율이 올바르게 계산되어야 한다."""
        report = generator.generate()
        assert report["summary"]["pass_rate"] == 40.0  # 2/5 = 40%

    def test_by_category_grouping(self, generator):
        """카테고리별 그룹핑이 올바르게 동작해야 한다."""
        report = generator.generate()
        by_cat = report["by_category"]
        assert "암호화" in by_cat
        assert "인증" in by_cat
        assert "파일시스템" in by_cat
        assert len(by_cat["암호화"]) == 1
        assert len(by_cat["인증"]) == 3

    def test_meta_has_target_host(self, generator):
        """메타 정보에 대상 호스트가 포함되어야 한다."""
        report = generator.generate()
        assert report["meta"]["target_host"] == "127.0.0.1"

    def test_results_serialized(self, generator):
        """results 목록이 딕셔너리로 직렬화되어야 한다."""
        report = generator.generate()
        for r in report["results"]:
            assert isinstance(r, dict)
            assert "id" in r
            assert "status" in r


class TestEmptyResults:
    """빈 결과에 대한 테스트"""

    def test_empty_results(self, sample_config):
        """빈 결과에서 pass_rate는 0이어야 한다."""
        gen = ReportGenerator(results=[], config=sample_config)
        report = gen.generate()
        assert report["summary"]["total"] == 0
        assert report["summary"]["pass_rate"] == 0.0
        assert report["by_category"] == {}
