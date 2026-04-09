"""
그레이박스 검사 - 암호화 알고리즘 분석기 단위 테스트
"""

from unittest.mock import patch

import pytest

from src.engines.graybox.crypto_analyzer import CryptoAnalyzer
from src.models import TestStatus


@pytest.fixture
def analyzer(sample_config):
    return CryptoAnalyzer(sample_config)


class TestForbiddenAlgorithms:
    """금지 암호 알고리즘 탐지 테스트"""

    def test_skip_when_no_binaries(self, analyzer):
        """바이너리를 찾지 못하면 SKIP이어야 한다."""
        with patch.object(analyzer, "_find_binaries", return_value=[]):
            result = analyzer.check_forbidden_algorithms()
        assert result.status == TestStatus.SKIP

    def test_fail_when_des_found(self, analyzer, tmp_path):
        """DES 문자열이 탐지되면 FAIL이어야 한다."""
        fake_bin = tmp_path / "libcrypto.so"
        fake_bin.write_bytes(b"DES_ecb_encrypt\x00AES_encrypt\x00")

        with (
            patch.object(analyzer, "_find_binaries", return_value=[fake_bin]),
            patch.object(analyzer, "_get_strings", return_value=["DES_ecb_encrypt", "AES_encrypt"]),
        ):
            result = analyzer.check_forbidden_algorithms()
        assert result.status == TestStatus.FAIL

    def test_pass_when_no_weak_algo(self, analyzer, tmp_path):
        """금지 알고리즘이 없으면 PASS이어야 한다."""
        fake_bin = tmp_path / "libssl.so"
        fake_bin.write_bytes(b"AES_encrypt\x00SHA256\x00")

        with (
            patch.object(analyzer, "_find_binaries", return_value=[fake_bin]),
            patch.object(analyzer, "_get_strings", return_value=["AES_encrypt", "SHA256_Init"]),
        ):
            result = analyzer.check_forbidden_algorithms()
        assert result.status == TestStatus.PASS

    def test_result_id(self, analyzer):
        """결과 ID가 CRYPT-004이어야 한다."""
        with patch.object(analyzer, "_find_binaries", return_value=[]):
            result = analyzer.check_forbidden_algorithms()
        assert result.id == "CRYPT-004"
        assert result.engine == "graybox"
