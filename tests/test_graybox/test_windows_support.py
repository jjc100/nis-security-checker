"""
Windows/.NET/C++ 프로젝트 대상 그레이박스 검사 단위 테스트
tmp_path fixture 기반으로 실제 NVR4 전체 스캔 없이 동작 검증이 가능합니다.
"""

import pytest
from pathlib import Path
from unittest.mock import patch

from src.engines.graybox.filesystem_analyzer import FilesystemAnalyzer, _get_scan_roots
from src.engines.graybox.crypto_analyzer import CryptoAnalyzer, _extract_strings_from_binary
from src.engines.graybox.hardcoded_key_scanner import HardcodedKeyScanner
from src.engines.graybox.hash_analyzer import HashAnalyzer
from src.engines.graybox.log_analyzer import LogAnalyzer
from src.engines.graybox.integrity_checker import IntegrityChecker
from src.engines.graybox.cve_scanner import CVEScanner, _extract_nuget_packages
from src.engines.graybox.memory_analyzer import MemoryAnalyzer
from src.models import TestStatus


# ────────────────────────────────────────────────────────────────────────────────
# 공통 픽스처
# ────────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def windows_config(tmp_path):
    """Windows 프로젝트 경로가 설정된 테스트용 config 픽스처"""
    return {
        "target": {
            "project_path": str(tmp_path),
        },
        "features": {},
        "nvd": {"api_key": "", "product_name": "", "vendor": ""},
        "integrity_baseline": {},
    }


@pytest.fixture
def windows_config_with_source(tmp_path):
    """source_paths까지 설정된 테스트용 config 픽스처"""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    return {
        "target": {
            "project_path": str(tmp_path),
            "source_paths": [str(src_dir)],
        },
        "features": {},
        "nvd": {"api_key": "", "product_name": "", "vendor": ""},
        "integrity_baseline": {},
    }


@pytest.fixture
def sample_config():
    """기존 테스트 호환용 기본 설정 픽스처"""
    return {
        "target": {
            "host": "127.0.0.1",
            "ports": {"https": 8443, "rtsp": 5540, "http": 8080, "ssh": 2222},
        },
        "features": {},
        "nvd": {"api_key": "", "product_name": "", "vendor": ""},
        "integrity_baseline": {},
    }


# ────────────────────────────────────────────────────────────────────────────────
# 설정 헬퍼 함수 테스트
# ────────────────────────────────────────────────────────────────────────────────

class TestGetScanRoots:
    """_get_scan_roots 함수 테스트"""

    def test_project_path_is_used_when_exists(self, tmp_path):
        """존재하는 project_path가 탐색 루트에 포함되어야 한다."""
        config = {"target": {"project_path": str(tmp_path)}}
        roots = _get_scan_roots(config)
        assert any(r == tmp_path for r in roots)

    def test_nonexistent_project_path_is_ignored(self, tmp_path):
        """존재하지 않는 project_path는 무시되어야 한다."""
        config = {"target": {"project_path": str(tmp_path / "nonexistent")}}
        roots = _get_scan_roots(config)
        assert not roots

    def test_source_paths_take_priority(self, tmp_path):
        """source_paths가 명시된 경우 해당 경로가 포함되어야 한다."""
        src = tmp_path / "src"
        src.mkdir()
        config = {
            "target": {
                "project_path": str(tmp_path),
                "source_paths": [str(src)],
            }
        }
        roots = _get_scan_roots(config)
        assert any(r == src for r in roots)

    def test_build_output_included_when_enabled(self, tmp_path):
        """scan_build_outputs=true일 때 build_output_path가 포함되어야 한다."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        config = {
            "target": {
                "project_path": str(tmp_path),
                "build_output_path": str(bin_dir),
                "scan_build_outputs": True,
            }
        }
        roots = _get_scan_roots(config)
        assert any(r == bin_dir for r in roots)

    def test_build_output_excluded_when_disabled(self, tmp_path):
        """scan_build_outputs=false일 때 build_output_path가 제외되어야 한다."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        config = {
            "target": {
                "project_path": str(tmp_path),
                "build_output_path": str(bin_dir),
                "scan_build_outputs": False,
            }
        }
        roots = _get_scan_roots(config)
        assert not any(r == bin_dir for r in roots)


# ────────────────────────────────────────────────────────────────────────────────
# FilesystemAnalyzer 테스트 (Windows 모드)
# ────────────────────────────────────────────────────────────────────────────────

class TestFilesystemAnalyzerWindows:
    """Windows 프로젝트 대상 FilesystemAnalyzer 테스트"""

    def test_find_cs_source_files(self, tmp_path, windows_config):
        """project_path에서 .cs 파일을 탐색해야 한다."""
        cs_file = tmp_path / "Program.cs"
        cs_file.write_text("// C# 소스", encoding="utf-8")

        analyzer = FilesystemAnalyzer(windows_config)
        found = analyzer._find_config_files()
        assert any(f.name == "Program.cs" for f in found)

    def test_find_config_xml_files(self, tmp_path, windows_config):
        """project_path에서 .config/.xml 파일을 탐색해야 한다."""
        cfg_file = tmp_path / "App.config"
        cfg_file.write_text("<configuration/>", encoding="utf-8")

        analyzer = FilesystemAnalyzer(windows_config)
        found = analyzer._find_config_files()
        assert any(f.name == "App.config" for f in found)

    def test_excluded_dirs_skipped(self, tmp_path, windows_config):
        """.git 디렉터리 내 파일은 탐색에서 제외되어야 한다."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        git_cfg = git_dir / "config"
        git_cfg.write_text("[core]", encoding="utf-8")

        analyzer = FilesystemAnalyzer(windows_config)
        found = analyzer._find_config_files()
        # .git/config 파일은 SOURCE_EXTENSIONS에 없으므로 탐색 대상이 아님
        assert not any(".git" in str(f) for f in found)

    def test_plaintext_password_in_config_file(self, tmp_path, windows_config):
        """App.config에 평문 패스워드가 있으면 FAIL이어야 한다."""
        cfg_file = tmp_path / "App.config"
        cfg_file.write_text(
            '<add key="password" value="mysecret123"/>', encoding="utf-8"
        )

        analyzer = FilesystemAnalyzer(windows_config)
        result = analyzer.check_plaintext_passwords()
        assert result.status == TestStatus.FAIL

    def test_no_plaintext_password_passes(self, tmp_path, windows_config):
        """평문 패스워드가 없으면 PASS이어야 한다."""
        cs_file = tmp_path / "Program.cs"
        cs_file.write_text("// 평문 패스워드 없음\nvar x = 1;", encoding="utf-8")

        analyzer = FilesystemAnalyzer(windows_config)
        result = analyzer.check_plaintext_passwords()
        assert result.status == TestStatus.PASS

    def test_no_files_returns_pass_with_zero_count(self, tmp_path, windows_config):
        """탐색 결과 파일이 없으면 PASS(0개 파일)이어야 한다."""
        analyzer = FilesystemAnalyzer(windows_config)
        result = analyzer.check_plaintext_passwords()
        assert result.status == TestStatus.PASS
        assert "0개" in result.details


# ────────────────────────────────────────────────────────────────────────────────
# CryptoAnalyzer 테스트 (소스 파일 + Python 바이너리 추출)
# ────────────────────────────────────────────────────────────────────────────────

class TestExtractStringsFromBinary:
    """_extract_strings_from_binary 유틸 함수 테스트"""

    def test_extracts_ascii_strings(self):
        """바이너리에서 ASCII 문자열을 올바르게 추출해야 한다."""
        data = b"\x00\x01DES_ecb_encrypt\x00\x00AES_encrypt\x00"
        result = _extract_strings_from_binary(data, min_length=6)
        assert "DES_ecb_encrypt" in result
        assert "AES_encrypt" in result

    def test_filters_by_min_length(self):
        """최소 길이 미만 문자열은 제외되어야 한다."""
        data = b"\x00ABC\x00ABCDEFGH\x00"
        result = _extract_strings_from_binary(data, min_length=6)
        assert "ABC" not in result
        assert "ABCDEFGH" in result


class TestCryptoAnalyzerWindows:
    """Windows 프로젝트 대상 CryptoAnalyzer 테스트"""

    def test_fail_on_md5_in_cs_source(self, tmp_path, windows_config):
        """.cs 소스에서 MD5.Create() 패턴이 탐지되면 FAIL이어야 한다."""
        cs_file = tmp_path / "Crypto.cs"
        cs_file.write_text(
            "var md5 = MD5.Create();\nmd5.ComputeHash(data);",
            encoding="utf-8",
        )
        analyzer = CryptoAnalyzer(windows_config)
        result = analyzer.check_forbidden_algorithms()
        assert result.status == TestStatus.FAIL

    def test_fail_on_des_in_cs_source(self, tmp_path, windows_config):
        """.cs 소스에서 DESCryptoServiceProvider가 탐지되면 FAIL이어야 한다."""
        cs_file = tmp_path / "DES.cs"
        cs_file.write_text(
            "var des = new DESCryptoServiceProvider();",
            encoding="utf-8",
        )
        analyzer = CryptoAnalyzer(windows_config)
        result = analyzer.check_forbidden_algorithms()
        assert result.status == TestStatus.FAIL

    def test_fail_on_md5_in_cpp_source(self, tmp_path, windows_config):
        """.cpp 소스에서 MD5_Init 패턴이 탐지되면 FAIL이어야 한다."""
        cpp_file = tmp_path / "hash.cpp"
        cpp_file.write_text(
            "#include <openssl/md5.h>\nMD5_CTX ctx;\nMD5_Init(&ctx);",
            encoding="utf-8",
        )
        analyzer = CryptoAnalyzer(windows_config)
        result = analyzer.check_forbidden_algorithms()
        assert result.status == TestStatus.FAIL

    def test_pass_on_aes_only(self, tmp_path, windows_config):
        """AES만 사용하면 PASS이어야 한다."""
        cs_file = tmp_path / "Safe.cs"
        cs_file.write_text(
            "using System.Security.Cryptography;\nvar aes = Aes.Create();",
            encoding="utf-8",
        )
        analyzer = CryptoAnalyzer(windows_config)
        result = analyzer.check_forbidden_algorithms()
        assert result.status == TestStatus.PASS

    def test_skip_when_no_project_path(self, sample_config):
        """project_path가 없고 Linux 경로도 없으면 SKIP이어야 한다."""
        analyzer = CryptoAnalyzer(sample_config)
        with (
            patch.object(analyzer, "_find_source_files", return_value=[]),
            patch.object(analyzer, "_find_binaries", return_value=[]),
        ):
            result = analyzer.check_forbidden_algorithms()
        assert result.status == TestStatus.SKIP

    def test_result_id_and_engine(self, sample_config):
        """결과 ID가 CRYPT-004이고 engine이 graybox이어야 한다."""
        analyzer = CryptoAnalyzer(sample_config)
        with (
            patch.object(analyzer, "_find_source_files", return_value=[]),
            patch.object(analyzer, "_find_binaries", return_value=[]),
        ):
            result = analyzer.check_forbidden_algorithms()
        assert result.id == "CRYPT-004"
        assert result.engine == "graybox"


# ────────────────────────────────────────────────────────────────────────────────
# HardcodedKeyScanner 테스트 (소스 파일)
# ────────────────────────────────────────────────────────────────────────────────

class TestHardcodedKeyScannerWindows:
    """Windows 프로젝트 대상 HardcodedKeyScanner 테스트"""

    def test_fail_on_pem_private_key_in_source(self, tmp_path, windows_config):
        """.cs 파일에 PEM 개인키가 있으면 FAIL이어야 한다."""
        cs_file = tmp_path / "Keys.cs"
        cs_file.write_text(
            'string key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIE...";',
            encoding="utf-8",
        )
        scanner = HardcodedKeyScanner(windows_config)
        result = scanner.check_hardcoded_keys()
        assert result.status == TestStatus.FAIL

    def test_fail_on_dotnet_connection_string(self, tmp_path, windows_config):
        """App.config에서 connectionString 내 패스워드가 탐지되면 FAIL이어야 한다."""
        cfg_file = tmp_path / "App.config"
        cfg_file.write_text(
            '<add name="db" connectionString="Server=.;password=mysecret123"/>',
            encoding="utf-8",
        )
        scanner = HardcodedKeyScanner(windows_config)
        result = scanner.check_hardcoded_keys()
        assert result.status == TestStatus.FAIL

    def test_pass_on_clean_source(self, tmp_path, windows_config):
        """하드코딩 키가 없으면 PASS이어야 한다."""
        cs_file = tmp_path / "Clean.cs"
        cs_file.write_text(
            "using System;\nclass Program { static void Main() {} }",
            encoding="utf-8",
        )
        scanner = HardcodedKeyScanner(windows_config)
        result = scanner.check_hardcoded_keys()
        assert result.status == TestStatus.PASS

    def test_skip_when_no_files(self, sample_config):
        """파일이 없으면 SKIP이어야 한다."""
        scanner = HardcodedKeyScanner(sample_config)
        with (
            patch.object(scanner, "_find_source_files", return_value=[]),
            patch.object(scanner, "_find_binaries", return_value=[]),
        ):
            result = scanner.check_hardcoded_keys()
        assert result.status == TestStatus.SKIP

    def test_result_id(self, sample_config):
        """결과 ID가 CRYPT-008이어야 한다."""
        scanner = HardcodedKeyScanner(sample_config)
        with (
            patch.object(scanner, "_find_source_files", return_value=[]),
            patch.object(scanner, "_find_binaries", return_value=[]),
        ):
            result = scanner.check_hardcoded_keys()
        assert result.id == "CRYPT-008"


# ────────────────────────────────────────────────────────────────────────────────
# HashAnalyzer 테스트 (소스 코드 해시 패턴)
# ────────────────────────────────────────────────────────────────────────────────

class TestHashAnalyzerWindows:
    """Windows 프로젝트 대상 HashAnalyzer 테스트"""

    def test_fail_on_md5_create_in_cs(self, tmp_path, windows_config):
        """.cs 파일에서 MD5.Create() 패턴이 탐지되면 FAIL이어야 한다."""
        cs_file = tmp_path / "Hash.cs"
        cs_file.write_text(
            "var hash = MD5.Create();\nhash.ComputeHash(data);",
            encoding="utf-8",
        )
        analyzer = HashAnalyzer(windows_config)
        result = analyzer.check_hash_format()
        assert result.status == TestStatus.FAIL

    def test_fail_on_sha1managed_in_cs(self, tmp_path, windows_config):
        """.cs 파일에서 SHA1Managed 패턴이 탐지되면 FAIL이어야 한다."""
        cs_file = tmp_path / "Sha1.cs"
        cs_file.write_text(
            "var sha = new SHA1Managed();\nsha.ComputeHash(data);",
            encoding="utf-8",
        )
        analyzer = HashAnalyzer(windows_config)
        result = analyzer.check_hash_format()
        assert result.status == TestStatus.FAIL

    def test_fail_on_md5_init_in_cpp(self, tmp_path, windows_config):
        """.cpp 파일에서 MD5_Init 패턴이 탐지되면 FAIL이어야 한다."""
        cpp_file = tmp_path / "hash.cpp"
        cpp_file.write_text(
            "MD5_CTX ctx;\nMD5_Init(&ctx);\nMD5_Update(&ctx, data, len);",
            encoding="utf-8",
        )
        analyzer = HashAnalyzer(windows_config)
        result = analyzer.check_hash_format()
        assert result.status == TestStatus.FAIL

    def test_pass_on_sha256_in_cs(self, tmp_path, windows_config):
        """SHA256만 사용하면 PASS이어야 한다."""
        cs_file = tmp_path / "SafeHash.cs"
        cs_file.write_text(
            "var sha = SHA256.Create();\nsha.ComputeHash(data);",
            encoding="utf-8",
        )
        analyzer = HashAnalyzer(windows_config)
        result = analyzer.check_hash_format()
        assert result.status == TestStatus.PASS


# ────────────────────────────────────────────────────────────────────────────────
# LogAnalyzer 테스트 (소스 코드 로깅)
# ────────────────────────────────────────────────────────────────────────────────

class TestLogAnalyzerWindows:
    """Windows 프로젝트 대상 LogAnalyzer 테스트"""

    def test_fail_on_sensitive_logging_in_cs(self, tmp_path, windows_config):
        """.cs 소스에서 로그에 password를 출력하면 FAIL이어야 한다."""
        cs_file = tmp_path / "Auth.cs"
        cs_file.write_text(
            'Logger.Info($"login: password={userPassword}");',
            encoding="utf-8",
        )
        analyzer = LogAnalyzer(windows_config)
        result = analyzer.check_no_sensitive_data()
        assert result.status == TestStatus.FAIL

    def test_pass_on_safe_logging(self, tmp_path, windows_config):
        """민감정보를 로깅하지 않으면 PASS이어야 한다."""
        cs_file = tmp_path / "SafeAuth.cs"
        cs_file.write_text(
            'Logger.Info("사용자 로그인 성공");',
            encoding="utf-8",
        )
        analyzer = LogAnalyzer(windows_config)
        result = analyzer.check_no_sensitive_data()
        assert result.status == TestStatus.PASS

    def test_login_event_detected_in_source(self, tmp_path, windows_config):
        """소스 코드에 로그인 이벤트 로깅 구문이 있으면 PASS이어야 한다."""
        cs_file = tmp_path / "LoginHandler.cs"
        cs_file.write_text(
            'logger.Log("login success");\nlogger.Log("login failed");',
            encoding="utf-8",
        )
        analyzer = LogAnalyzer(windows_config)
        result = analyzer.check_required_events()
        assert result.status == TestStatus.PASS

    def test_result_ids(self, tmp_path, windows_config):
        """결과 ID가 LOG-001, LOG-002, LOG-003이어야 한다."""
        analyzer = LogAnalyzer(windows_config)
        results = analyzer.run()
        ids = {r.id for r in results}
        assert "LOG-001" in ids
        assert "LOG-002" in ids
        assert "LOG-003" in ids


# ────────────────────────────────────────────────────────────────────────────────
# IntegrityChecker 테스트 (project_path 기반)
# ────────────────────────────────────────────────────────────────────────────────

class TestIntegrityCheckerWindows:
    """Windows 프로젝트 대상 IntegrityChecker 테스트"""

    def test_manual_when_no_baseline_but_build_files_found(self, tmp_path):
        """integrity_baseline이 없고 빌드 산출물이 있으면 MANUAL이어야 한다."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        exe_file = bin_dir / "NVR4.exe"
        exe_file.write_bytes(b"\x4d\x5a\x90\x00")  # PE 헤더

        config = {
            "target": {
                "project_path": str(tmp_path),
                "build_output_path": str(bin_dir),
                "scan_build_outputs": True,
            },
            "integrity_baseline": {},
        }
        checker = IntegrityChecker(config)
        result = checker.check_file_integrity()
        assert result.status == TestStatus.MANUAL
        assert "NVR4.exe" in result.details

    def test_skip_when_no_baseline_and_no_build_files(self, tmp_path, windows_config):
        """integrity_baseline이 없고 빌드 산출물도 없으면 SKIP이어야 한다."""
        checker = IntegrityChecker(windows_config)
        result = checker.check_file_integrity()
        assert result.status == TestStatus.SKIP

    def test_pass_when_hash_matches(self, tmp_path):
        """설정된 해시값과 실제 해시가 일치하면 PASS이어야 한다."""
        from src.utils.crypto import sha256_file
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"test binary data")
        expected_hash = sha256_file(test_file)

        config = {
            "target": {"project_path": str(tmp_path)},
            "integrity_baseline": {str(test_file): expected_hash},
        }
        checker = IntegrityChecker(config)
        result = checker.check_file_integrity()
        assert result.status == TestStatus.PASS

    def test_fail_when_hash_mismatch(self, tmp_path):
        """해시값이 불일치하면 FAIL이어야 한다."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"test binary data")

        config = {
            "target": {"project_path": str(tmp_path)},
            "integrity_baseline": {
                str(test_file): "a" * 64  # 잘못된 해시
            },
        }
        checker = IntegrityChecker(config)
        result = checker.check_file_integrity()
        assert result.status == TestStatus.FAIL


# ────────────────────────────────────────────────────────────────────────────────
# CVEScanner 테스트 (NuGet 패키지 추출)
# ────────────────────────────────────────────────────────────────────────────────

class TestExtractNugetPackages:
    """_extract_nuget_packages 유틸 함수 테스트"""

    def test_packages_config_format(self, tmp_path):
        """packages.config 형식에서 패키지를 올바르게 추출해야 한다."""
        cfg = tmp_path / "packages.config"
        cfg.write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<packages>\n"
            '  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net48" />\n'
            '  <package id="log4net" version="2.0.15" targetFramework="net48" />\n'
            "</packages>\n",
            encoding="utf-8",
        )
        packages = _extract_nuget_packages(cfg)
        assert ("Newtonsoft.Json", "13.0.1") in packages
        assert ("log4net", "2.0.15") in packages

    def test_csproj_package_reference_format(self, tmp_path):
        """.csproj PackageReference 형식에서 패키지를 올바르게 추출해야 한다."""
        csproj = tmp_path / "App.csproj"
        csproj.write_text(
            "<Project Sdk=\"Microsoft.NET.Sdk\">\n"
            "  <ItemGroup>\n"
            '    <PackageReference Include="Serilog" Version="3.0.1" />\n'
            '    <PackageReference Include="NLog" Version="5.1.0" />\n'
            "  </ItemGroup>\n"
            "</Project>\n",
            encoding="utf-8",
        )
        packages = _extract_nuget_packages(csproj)
        assert ("Serilog", "3.0.1") in packages
        assert ("NLog", "5.1.0") in packages

    def test_empty_file_returns_empty_list(self, tmp_path):
        """패키지 참조가 없는 파일은 빈 목록을 반환해야 한다."""
        cfg = tmp_path / "empty.config"
        cfg.write_text("<configuration/>", encoding="utf-8")
        packages = _extract_nuget_packages(cfg)
        assert packages == []


class TestCVEScannerWindows:
    """Windows 프로젝트 대상 CVEScanner 테스트"""

    def test_skip_when_no_nuget_files(self, tmp_path, windows_config):
        """NuGet 파일이 없으면 SKIP이어야 한다."""
        scanner = CVEScanner(windows_config)
        result = scanner.check_nuget_cve_vulnerabilities()
        assert result.status == TestStatus.SKIP

    def test_manual_without_api_key_when_packages_found(self, tmp_path, windows_config):
        """API 키 없이 NuGet 패키지를 찾으면 MANUAL이어야 한다."""
        cfg = tmp_path / "packages.config"
        cfg.write_text(
            '<packages>\n'
            '  <package id="Newtonsoft.Json" version="13.0.1" />\n'
            '</packages>\n',
            encoding="utf-8",
        )
        scanner = CVEScanner(windows_config)
        result = scanner.check_nuget_cve_vulnerabilities()
        assert result.status == TestStatus.MANUAL
        assert "Newtonsoft.Json" in result.details

    def test_nuget_result_id(self, tmp_path, windows_config):
        """NuGet CVE 검사 결과 ID가 SW-001-NUGET이어야 한다."""
        scanner = CVEScanner(windows_config)
        result = scanner.check_nuget_cve_vulnerabilities()
        assert result.id == "SW-001-NUGET"

    def test_run_includes_nuget_check_with_project_path(self, tmp_path, windows_config):
        """project_path가 있으면 run() 결과에 NuGet 검사가 포함되어야 한다."""
        scanner = CVEScanner(windows_config)
        results = scanner.run()
        ids = [r.id for r in results]
        assert "SW-001-NUGET" in ids


# ────────────────────────────────────────────────────────────────────────────────
# MemoryAnalyzer 테스트 (소스 코드 메모리 보안)
# ────────────────────────────────────────────────────────────────────────────────

class TestMemoryAnalyzerWindows:
    """Windows 프로젝트 대상 MemoryAnalyzer 테스트"""

    def test_fail_on_plaintext_password_variable_in_cs(self, tmp_path, windows_config):
        """.cs 소스에서 string password = "..." 패턴이 탐지되면 FAIL이어야 한다."""
        cs_file = tmp_path / "Auth.cs"
        cs_file.write_text(
            'string password = "mypassword123";\nDoLogin(password);',
            encoding="utf-8",
        )
        analyzer = MemoryAnalyzer(windows_config)
        result = analyzer.check_plaintext_credentials_in_memory()
        assert result.status == TestStatus.FAIL

    def test_fail_on_char_array_password_in_cpp(self, tmp_path, windows_config):
        """.cpp 소스에서 char password[...] 패턴이 탐지되면 FAIL이어야 한다."""
        cpp_file = tmp_path / "auth.cpp"
        cpp_file.write_text(
            "char password[64];\nstrcpy(password, input);",
            encoding="utf-8",
        )
        analyzer = MemoryAnalyzer(windows_config)
        result = analyzer.check_plaintext_credentials_in_memory()
        assert result.status == TestStatus.FAIL

    def test_pass_on_clean_source(self, tmp_path, windows_config):
        """메모리 보안 이슈가 없으면 PASS이어야 한다."""
        cs_file = tmp_path / "Safe.cs"
        cs_file.write_text(
            "using System.Security;\nvar ss = new SecureString();\n",
            encoding="utf-8",
        )
        analyzer = MemoryAnalyzer(windows_config)
        result = analyzer.check_plaintext_credentials_in_memory()
        assert result.status == TestStatus.PASS

    def test_result_id(self, tmp_path, windows_config):
        """결과 ID가 MEM-001이어야 한다."""
        analyzer = MemoryAnalyzer(windows_config)
        result = analyzer.check_plaintext_credentials_in_memory()
        assert result.id == "MEM-001"
        assert result.engine == "graybox"

    def test_no_project_path_on_windows_returns_skip_not_attribute_error(self):
        """project_path 없이 Windows 플랫폼에서 실행해도 AttributeError가 발생하지 않아야 한다."""
        # project_path/source_paths가 없는 설정 (Windows 플랫폼에서 project_path 없이 실행하는 케이스)
        empty_config = {"target": {}, "features": {}}
        analyzer = MemoryAnalyzer(empty_config)
        # 수정 전에는 Windows에서 os.geteuid()가 없어 AttributeError가 발생했음.
        # 수정 후에는 Windows이면 SKIP, Linux이면 root 권한 없음으로 인한 SKIP이 반환되어야 한다.
        result = analyzer.check_plaintext_credentials_in_memory()
        assert result.id == "MEM-001"
        assert result.status in (TestStatus.SKIP, TestStatus.PASS)


# ────────────────────────────────────────────────────────────────────────────────
# Runner 설정 검증 테스트
# ────────────────────────────────────────────────────────────────────────────────

class TestRunnerConfigValidation:
    """Runner의 설정 검증 로직 테스트"""

    def _make_runner(self, mode: str) -> object:
        """테스트용 Runner 인스턴스를 생성합니다."""
        from src.runner import Runner
        return Runner(
            config_path="dummy.yaml",
            checklist_path="dummy_checklist.yaml",
            mode=mode,
        )

    def test_blackbox_mode_requires_host(self):
        """blackbox 모드에서 host가 없으면 오류 메시지를 반환해야 한다."""
        runner = self._make_runner("blackbox")
        config = {"target": {}, "features": {}}
        error = runner._validate_config(config)
        assert error is not None
        assert "host" in error.lower() or "blackbox" in error.lower()

    def test_blackbox_mode_passes_with_host(self):
        """blackbox 모드에서 host가 있으면 None을 반환해야 한다."""
        runner = self._make_runner("blackbox")
        config = {"target": {"host": "192.168.1.1"}, "features": {}}
        error = runner._validate_config(config)
        assert error is None

    def test_all_mode_no_host_skips_blackbox(self):
        """all 모드에서 host가 없으면 blackbox를 건너뛰어야 한다."""
        from src.runner import Runner
        runner = Runner(
            config_path="dummy.yaml",
            checklist_path="dummy_checklist.yaml",
            mode="all",
        )
        config = {"target": {"project_path": "/tmp/project"}, "features": {}}
        assert not runner._should_run_blackbox(config)
        assert runner._should_run_graybox(config)

    def test_all_mode_with_host_runs_blackbox(self):
        """all 모드에서 host가 있으면 blackbox를 실행해야 한다."""
        from src.runner import Runner
        runner = Runner(
            config_path="dummy.yaml",
            checklist_path="dummy_checklist.yaml",
            mode="all",
        )
        config = {"target": {"host": "192.168.1.1"}, "features": {}}
        assert runner._should_run_blackbox(config)

    def test_graybox_mode_always_runs(self):
        """graybox 모드는 project_path 유무에 무관하게 실행 결정이 True이어야 한다."""
        from src.runner import Runner
        runner = Runner(
            config_path="dummy.yaml",
            checklist_path="dummy_checklist.yaml",
            mode="graybox",
        )
        config = {"target": {}, "features": {}}
        assert runner._should_run_graybox(config)
