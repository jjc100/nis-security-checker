"""
검사 실행기 모듈
YAML 설정을 로드하고, 선택된 엔진을 실행하여 결과를 수집한 후 리포트를 생성합니다.
"""

import logging
from pathlib import Path
from typing import Optional

import yaml

from src.models import TestResult, TestStatus
from src.utils.logger import setup_logger


class Runner:
    """검사 엔진 오케스트레이터"""

    def __init__(
        self,
        config_path: str,
        checklist_path: str,
        mode: str = "all",
        output_path: str = "output/report.html",
        output_format: str = "html",
        log_file: Optional[str] = None,
        verbose: bool = False,
    ) -> None:
        self.config_path = config_path
        self.checklist_path = checklist_path
        self.mode = mode
        self.output_path = output_path
        self.output_format = output_format

        log_level = logging.DEBUG if verbose else logging.INFO
        self.logger = setup_logger("nis_checker", log_file, log_level)

    def _load_config(self) -> dict:
        """대상 설정 YAML 파일을 로드합니다."""
        with open(self.config_path, encoding="utf-8") as f:
            return yaml.safe_load(f)

    def _load_checklist(self) -> list[dict]:
        """체크리스트 항목 YAML 파일을 로드합니다."""
        with open(self.checklist_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("items", [])

    def _run_blackbox(self, config: dict) -> list[TestResult]:
        """블랙박스 검사 엔진들을 실행합니다."""
        results: list[TestResult] = []
        host = config["target"]["host"]
        ports = config["target"]["ports"]
        features = config.get("features", {})

        self.logger.info("블랙박스 검사 시작: %s", host)

        # TLS 검사
        try:
            from src.engines.blackbox.tls_checker import TLSChecker
            checker = TLSChecker(host, ports.get("https", 443))
            results.extend(checker.run())
        except Exception as e:
            self.logger.warning("TLS 검사 오류: %s", e)
            results.append(TestResult(
                id="CRYPT-001", name="TLS 버전 검사", category="암호화",
                status=TestStatus.ERROR, engine="blackbox", details=str(e),
            ))

        # 포트 스캔
        try:
            from src.engines.blackbox.port_scanner import PortScanner
            scanner = PortScanner(host)
            results.extend(scanner.run())
        except Exception as e:
            self.logger.warning("포트 스캔 오류: %s", e)

        # 로그인 잠금 검사
        try:
            from src.engines.blackbox.login_tester import LoginTester
            creds = config.get("credentials", {}).get("admin", {})
            tester = LoginTester(
                host=host,
                port=ports.get("https", 443),
                username=creds.get("username", "admin"),
                max_attempts=config.get("max_login_attempts", 5),
            )
            results.extend(tester.run())
        except Exception as e:
            self.logger.warning("로그인 잠금 검사 오류: %s", e)

        # 세션 검사
        try:
            from src.engines.blackbox.session_tester import SessionTester
            tester = SessionTester(host=host, port=ports.get("https", 443))
            results.extend(tester.run())
        except Exception as e:
            self.logger.warning("세션 검사 오류: %s", e)

        # SSH 검사
        if features.get("has_ssh", False):
            try:
                from src.engines.blackbox.ssh_checker import SSHChecker
                checker = SSHChecker(host, ports.get("ssh", 22))
                results.extend(checker.run())
            except Exception as e:
                self.logger.warning("SSH 검사 오류: %s", e)

        # RTSP/ONVIF 프로토콜 인증 검사
        try:
            from src.engines.blackbox.protocol_auth import ProtocolAuthChecker
            checker = ProtocolAuthChecker(
                host=host,
                rtsp_port=ports.get("rtsp", 554),
                http_port=ports.get("http", 80),
                has_rtsp=features.get("has_rtsp", False),
                has_onvif=features.get("has_onvif", False),
            )
            results.extend(checker.run())
        except Exception as e:
            self.logger.warning("프로토콜 인증 검사 오류: %s", e)

        # API 인증 검사
        try:
            from src.engines.blackbox.api_auth_tester import APIAuthTester
            tester = APIAuthTester(host=host, port=ports.get("https", 443))
            results.extend(tester.run())
        except Exception as e:
            self.logger.warning("API 인증 검사 오류: %s", e)

        # 기본 계정 검사
        try:
            from src.engines.blackbox.default_cred_checker import DefaultCredChecker
            default_creds = config.get("default_credentials", [])
            checker = DefaultCredChecker(
                host=host,
                port=ports.get("https", 443),
                default_credentials=default_creds,
            )
            results.extend(checker.run())
        except Exception as e:
            self.logger.warning("기본 계정 검사 오류: %s", e)

        self.logger.info("블랙박스 검사 완료. 결과 %d건", len(results))
        return results

    def _run_graybox(self, config: dict) -> list[TestResult]:
        """그레이박스 검사 엔진들을 실행합니다."""
        results: list[TestResult] = []
        self.logger.info("그레이박스 검사 시작")

        modules = [
            ("src.engines.graybox.filesystem_analyzer", "FilesystemAnalyzer"),
            ("src.engines.graybox.crypto_analyzer", "CryptoAnalyzer"),
            ("src.engines.graybox.hash_analyzer", "HashAnalyzer"),
            ("src.engines.graybox.hardcoded_key_scanner", "HardcodedKeyScanner"),
            ("src.engines.graybox.iframe_checker", "IFrameChecker"),
            ("src.engines.graybox.log_analyzer", "LogAnalyzer"),
            ("src.engines.graybox.memory_analyzer", "MemoryAnalyzer"),
            ("src.engines.graybox.integrity_checker", "IntegrityChecker"),
            ("src.engines.graybox.cve_scanner", "CVEScanner"),
        ]

        for module_path, class_name in modules:
            try:
                import importlib
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name)
                checker = cls(config)
                results.extend(checker.run())
            except Exception as e:
                self.logger.warning("%s 실행 오류: %s", class_name, e)

        self.logger.info("그레이박스 검사 완료. 결과 %d건", len(results))
        return results

    def _run_checklist(self, config: dict, items: list[dict]) -> list[TestResult]:
        """체크리스트 엔진을 실행합니다."""
        self.logger.info("체크리스트 검사 시작")

        from src.engines.checklist.interactive import InteractiveChecklist
        features = config.get("features", {})
        checker = InteractiveChecklist(items=items, features=features)
        results = checker.run()

        self.logger.info("체크리스트 검사 완료. 결과 %d건", len(results))
        return results

    def run(self) -> int:
        """
        설정에 따라 검사를 실행하고 리포트를 생성합니다.

        Returns:
            종료 코드 (0: 성공, 1: 오류)
        """
        try:
            config = self._load_config()
            items = self._load_checklist()
        except Exception as e:
            self.logger.error("설정 로드 실패: %s", e)
            return 1

        all_results: list[TestResult] = []

        if self.mode in ("blackbox", "all"):
            all_results.extend(self._run_blackbox(config))

        if self.mode in ("graybox", "all"):
            all_results.extend(self._run_graybox(config))

        if self.mode in ("checklist", "all"):
            all_results.extend(self._run_checklist(config, items))

        # 리포트 생성
        try:
            from src.report.generator import ReportGenerator
            generator = ReportGenerator(results=all_results, config=config)
            report_data = generator.generate()

            from src.report.formatters import format_report
            format_report(report_data, self.output_path, self.output_format)

            self.logger.info("리포트 저장 완료: %s", self.output_path)
        except Exception as e:
            self.logger.error("리포트 생성 실패: %s", e)
            return 1

        # 검사 결과 요약 출력
        total = len(all_results)
        passed = sum(1 for r in all_results if r.status == TestStatus.PASS)
        failed = sum(1 for r in all_results if r.status == TestStatus.FAIL)
        errors = sum(1 for r in all_results if r.status == TestStatus.ERROR)

        self.logger.info(
            "검사 완료 - 전체: %d, 통과: %d, 실패: %d, 오류: %d",
            total, passed, failed, errors,
        )

        # 실패 항목이 있으면 종료 코드 1 반환
        return 0 if failed == 0 and errors == 0 else 1
