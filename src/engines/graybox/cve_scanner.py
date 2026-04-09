"""
그레이박스 검사 - CVE 취약점 스캔 모듈
NVD(National Vulnerability Database) API를 통해 CVE 취약점을 조회합니다.
Windows 프로젝트의 .csproj/.vcxproj/packages.config에서 NuGet 패키지를 추출하여 조회합니다.
"""

import re
from datetime import datetime
from pathlib import Path

import requests

from src.models import TestResult, TestStatus
from src.utils.path_validator import is_within_root, DEFAULT_EXCLUDE_DIRS, DEFAULT_MAX_DEPTH

# NVD API 엔드포인트
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CVSS 점수 임계값 (이 이상이면 위험)
CRITICAL_CVSS_THRESHOLD = 7.0

# NuGet 패키지 참조 파일 확장자 및 이름
NUGET_FILE_PATTERNS = [
    "packages.config",
    "*.csproj",
    "*.vcxproj",
    "Directory.Build.props",
    "*.props",
]

# 제외 디렉터리
EXCLUDED_DIRS = DEFAULT_EXCLUDE_DIRS


def _is_excluded(path: Path) -> bool:
    """제외 디렉터리 여부를 확인합니다."""
    return any(part in EXCLUDED_DIRS for part in path.parts)


def _extract_nuget_packages(file_path: Path) -> list[tuple[str, str]]:
    """
    NuGet 관련 파일에서 패키지명과 버전을 추출합니다.

    Returns:
        (패키지명, 버전) 튜플 목록
    """
    packages: list[tuple[str, str]] = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")

        # packages.config 형식: <package id="Newtonsoft.Json" version="13.0.1" .../>
        for m in re.finditer(
            r'<package\s+id="([^"]+)"\s+version="([^"]+)"',
            content,
            re.IGNORECASE,
        ):
            packages.append((m.group(1), m.group(2)))

        # .csproj PackageReference 형식: <PackageReference Include="..." Version="..."/>
        for m in re.finditer(
            r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"',
            content,
            re.IGNORECASE,
        ):
            packages.append((m.group(1), m.group(2)))

        # .csproj PackageReference (Version 별도 자식 요소)
        for m in re.finditer(
            r'<PackageReference\s+Include="([^"]+)"[^>]*>\s*<Version>([^<]+)</Version>',
            content,
            re.IGNORECASE | re.DOTALL,
        ):
            packages.append((m.group(1), m.group(2).strip()))

    except OSError:
        pass
    return packages


def _get_project_roots(config: dict) -> list[Path]:
    """설정에서 프로젝트 루트 경로 목록을 결정합니다."""
    target = config.get("target", {})
    roots: list[Path] = []

    source_paths = target.get("source_paths") or []
    for sp in source_paths:
        p = Path(sp)
        if p.exists():
            roots.append(p)

    project_path = target.get("project_path")
    if project_path:
        p = Path(project_path)
        if p.exists():
            roots.append(p)

    # 솔루션 경로가 있으면 부모 디렉터리를 루트로 추가
    solution_path = target.get("solution_path")
    if solution_path:
        p = Path(solution_path).parent
        if p.exists() and p not in roots:
            roots.append(p)

    return roots


class CVEScanner:
    """CVE 취약점 스캐너"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.engine = "graybox"

        nvd_config = config.get("nvd", {})
        self.api_key: str = nvd_config.get("api_key", "")
        self.product_name: str = nvd_config.get("product_name", "")
        self.vendor: str = nvd_config.get("vendor", "")
        self._project_roots = _get_project_roots(config)

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

    def _find_nuget_files(self, max_count: int = 50) -> list[Path]:
        """NuGet 패키지 참조 파일을 탐색합니다."""
        files: list[Path] = []
        seen: set[Path] = set()

        for root in self._project_roots:
            if not root.exists():
                continue
            resolved_root = root.resolve()
            for fpath in root.rglob("*"):
                if _is_excluded(fpath):
                    continue
                if not fpath.is_file():
                    continue
                name = fpath.name.lower()
                ext = fpath.suffix.lower()
                # packages.config, *.csproj, *.vcxproj, Directory.Build.props 등
                if name == "packages.config" or ext in {".csproj", ".vcxproj", ".props"}:
                    # 스캔 깊이 제한
                    try:
                        depth = len(fpath.relative_to(root).parts)
                        if depth > DEFAULT_MAX_DEPTH:
                            continue
                    except ValueError:
                        continue
                    resolved = fpath.resolve()
                    # 루트 바깥 경로(심볼릭 링크 우회 등) 방지
                    if not is_within_root(resolved, resolved_root):
                        continue
                    if resolved not in seen:
                        seen.add(resolved)
                        files.append(fpath)
                        if len(files) >= max_count:
                            return files
        return files

    def check_nuget_cve_vulnerabilities(self) -> TestResult:
        """NuGet 패키지에 대한 알려진 CVE 취약점을 조회합니다."""
        nuget_files = self._find_nuget_files()
        if not nuget_files:
            return TestResult(
                id="SW-001-NUGET",
                name="NuGet 패키지 CVE 취약점 검사",
                category="소프트웨어보안",
                status=TestStatus.SKIP,
                engine=self.engine,
                details=(
                    "NuGet 패키지 참조 파일(.csproj, packages.config)을 찾을 수 없습니다. "
                    "config의 project_path를 확인하세요."
                ),
                timestamp=datetime.now(),
            )

        # NuGet 패키지 추출
        all_packages: list[tuple[str, str]] = []
        for f in nuget_files:
            all_packages.extend(_extract_nuget_packages(f))

        if not all_packages:
            return TestResult(
                id="SW-001-NUGET",
                name="NuGet 패키지 CVE 취약점 검사",
                category="소프트웨어보안",
                status=TestStatus.SKIP,
                engine=self.engine,
                details=f"{len(nuget_files)}개 파일에서 NuGet 패키지 참조를 추출하지 못했습니다.",
                timestamp=datetime.now(),
            )

        # 중복 제거 (패키지명 기준)
        unique_packages = list({name: ver for name, ver in all_packages}.items())

        if not self.api_key:
            # API 키 없으면 패키지 목록만 보고
            pkg_list = ", ".join(f"{n}({v})" for n, v in unique_packages[:10])
            return TestResult(
                id="SW-001-NUGET",
                name="NuGet 패키지 CVE 취약점 검사",
                category="소프트웨어보안",
                status=TestStatus.MANUAL,
                engine=self.engine,
                details=(
                    f"발견된 NuGet 패키지 {len(unique_packages)}개: {pkg_list}... "
                    "NVD API 키(nvd.api_key)를 설정하면 자동 CVE 조회가 가능합니다."
                ),
                timestamp=datetime.now(),
            )

        # NVD API로 조회
        critical_cves: list[str] = []
        for pkg_name, pkg_ver in unique_packages[:20]:  # 최대 20개 패키지 조회
            keyword = f"{pkg_name} {pkg_ver}"
            cve_list = self._query_nvd(keyword, results_per_page=5)
            for item in cve_list:
                score = self._extract_cvss_score(item)
                if score >= CRITICAL_CVSS_THRESHOLD:
                    cve_id = item.get("cve", {}).get("id", "N/A")
                    critical_cves.append(f"{cve_id}({pkg_name}/{pkg_ver}, CVSS:{score})")

        if critical_cves:
            return TestResult(
                id="SW-001-NUGET",
                name="NuGet 패키지 CVE 취약점 검사",
                category="소프트웨어보안",
                status=TestStatus.FAIL,
                engine=self.engine,
                details=f"고위험 CVE 발견: {', '.join(critical_cves[:10])}",
                timestamp=datetime.now(),
            )

        return TestResult(
            id="SW-001-NUGET",
            name="NuGet 패키지 CVE 취약점 검사",
            category="소프트웨어보안",
            status=TestStatus.PASS,
            engine=self.engine,
            details=f"{len(unique_packages)}개 NuGet 패키지에 CVSS 7.0 이상 CVE 미탐지.",
            timestamp=datetime.now(),
        )

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
                details=(
                    f"'{keyword}'에 대한 CVE 정보를 가져올 수 없습니다. "
                    "NVD API 키가 필요하거나 네트워크 오류일 수 있습니다."
                ),
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
        results = [self.check_cve_vulnerabilities()]
        # Windows 프로젝트 루트가 있으면 NuGet 패키지 CVE 추가 검사
        if self._project_roots:
            results.append(self.check_nuget_cve_vulnerabilities())
        return results
