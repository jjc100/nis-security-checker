"""
그레이박스 검사 - CVE 취약점 스캔 모듈
NVD(National Vulnerability Database) API를 통해 CVE 취약점을 조회합니다.
"""

from datetime import datetime

import requests

from src.models import TestResult, TestStatus

# NVD API 엔드포인트
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CVSS 점수 임계값 (이 이상이면 위험)
CRITICAL_CVSS_THRESHOLD = 7.0


class CVEScanner:
    """CVE 취약점 스캐너"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"

        nvd_config = config.get("nvd", {})
        self.api_key: str = nvd_config.get("api_key", "")
        self.product_name: str = nvd_config.get("product_name", "")
        self.vendor: str = nvd_config.get("vendor", "")

    def _query_nvd(self, keyword: str, results_per_page: int = 20) -> list[dict]:
        """
        NVD API에 키워드 검색을 수행합니다.

        Args:
            keyword: 검색 키워드
            results_per_page: 페이지당 결과 수

        Returns:
            CVE 항목 목록
        """
        params: dict = {
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
        }
        headers: dict = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            resp = requests.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("vulnerabilities", [])
        except requests.RequestException:
            return []

    def _extract_cvss_score(self, cve_item: dict) -> float:
        """CVE 항목에서 CVSS 점수를 추출합니다."""
        cve = cve_item.get("cve", {})
        metrics = cve.get("metrics", {})

        # CVSS v3.1 우선
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                score = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                return float(score)
        return 0.0

    def check_cve_vulnerabilities(self) -> TestResult:
        """제품에 대한 알려진 CVE 취약점을 조회합니다."""
        if not self.product_name:
            return TestResult(
                id="SW-001",
                name="알려진 CVE 취약점 미존재",
                category="소프트웨어보안",
                status=TestStatus.SKIP,
                engine=self.engine,
                details="NVD 검색을 위한 제품명(nvd.product_name)이 설정되지 않았습니다.",
                timestamp=datetime.now(),
            )

        keyword = f"{self.vendor} {self.product_name}".strip() if self.vendor else self.product_name
        cve_list = self._query_nvd(keyword)

        if not cve_list:
            return TestResult(
                id="SW-001",
                name="알려진 CVE 취약점 미존재",
                category="소프트웨어보안",
                status=TestStatus.MANUAL,
                engine=self.engine,
                details=f"'{keyword}'에 대한 CVE 정보를 가져올 수 없습니다. NVD API 키가 필요하거나 네트워크 오류일 수 있습니다.",
                timestamp=datetime.now(),
            )

        # CVSS 7.0 이상의 고위험 CVE 필터링
        critical_cves = []
        for item in cve_list:
            score = self._extract_cvss_score(item)
            if score >= CRITICAL_CVSS_THRESHOLD:
                cve_id = item.get("cve", {}).get("id", "N/A")
                critical_cves.append(f"{cve_id}(CVSS:{score})")

        if critical_cves:
            return TestResult(
                id="SW-001",
                name="알려진 CVE 취약점 미존재",
                category="소프트웨어보안",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"고위험 CVE 발견: {', '.join(critical_cves[:10])}",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="SW-001",
            name="알려진 CVE 취약점 미존재",
            category="소프트웨어보안",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"'{keyword}' 제품에 대해 CVSS 7.0 이상 CVE 미탐지. (전체 조회: {len(cve_list)}건)",
            timestamp=datetime.now(),
        )

    def run(self) -> list[TestResult]:
        """CVE 스캔 검사를 실행합니다."""
        return [self.check_cve_vulnerabilities()]
