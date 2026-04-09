"""
그레이박스 검사 - 해시 분석기 단위 테스트
"""

from unittest.mock import patch

import pytest

from src.engines.graybox.hash_analyzer import HashAnalyzer
from src.models import TestStatus


@pytest.fixture
def analyzer(sample_config):
    return HashAnalyzer(sample_config)


class TestHashFormat:
    """해시 포맷 검사 테스트"""

    def test_skip_when_no_hashes(self, analyzer):
        """해시를 읽지 못하면 SKIP이어야 한다."""
        with patch.object(analyzer, "_read_password_db", return_value=[]):
            result = analyzer.check_hash_format()
        assert result.status == TestStatus.SKIP

    def test_fail_when_md5_hash(self, analyzer):
        """MD5 해시가 탐지되면 FAIL이어야 한다."""
        # $1$ 접두사 = MD5 crypt
        md5_hash = "$1$saltsalt$hashedvalue123456789012"
        with patch.object(analyzer, "_read_password_db", return_value=[md5_hash]):
            result = analyzer.check_hash_format()
        assert result.status == TestStatus.FAIL

    def test_pass_when_bcrypt_hash(self, analyzer):
        """bcrypt 해시가 사용되면 PASS이어야 한다."""
        bcrypt_hash = "$2b$12$saltsaltsaltsaltsalts.hashedpasswordhashedpasswordhashed"
        with patch.object(analyzer, "_read_password_db", return_value=[bcrypt_hash]):
            result = analyzer.check_hash_format()
        assert result.status == TestStatus.PASS

    def test_result_id(self, analyzer):
        """결과 ID가 CRYPT-005이어야 한다."""
        with patch.object(analyzer, "_read_password_db", return_value=[]):
            result = analyzer.check_hash_format()
        assert result.id == "CRYPT-005"
        assert result.engine == "graybox"


class TestSaltUsage:
    """솔트 사용 여부 검사 테스트"""

    def test_skip_when_no_hashes(self, analyzer):
        """해시가 없으면 SKIP이어야 한다."""
        with patch.object(analyzer, "_read_password_db", return_value=[]):
            result = analyzer.check_salt_usage()
        assert result.status == TestStatus.SKIP

    def test_pass_when_sha512_crypt(self, analyzer):
        """SHA-512 crypt 해시($6$)는 솔트 포함이므로 PASS이어야 한다."""
        sha512_hash = "$6$rounds=5000$saltsaltsalt$hashedvalue" + "a" * 50
        with patch.object(analyzer, "_read_password_db", return_value=[sha512_hash]):
            result = analyzer.check_salt_usage()
        assert result.status == TestStatus.PASS

    def test_result_id(self, analyzer):
        """결과 ID가 CRYPT-006이어야 한다."""
        with patch.object(analyzer, "_read_password_db", return_value=[]):
            result = analyzer.check_salt_usage()
        assert result.id == "CRYPT-006"


class TestPBKDF2Iterations:
    """PBKDF2 반복 횟수 검사 테스트"""

    def test_pass_when_iterations_sufficient(self, analyzer):
        """반복 횟수가 10,000 이상이면 PASS이어야 한다."""
        pbkdf2_hash = "pbkdf2_sha256$100000$saltsalt$hashedvalue=="
        with patch.object(analyzer, "_read_password_db", return_value=[pbkdf2_hash]):
            result = analyzer.check_pbkdf2_iterations()
        assert result.status == TestStatus.PASS

    def test_fail_when_iterations_too_low(self, analyzer):
        """반복 횟수가 10,000 미만이면 FAIL이어야 한다."""
        pbkdf2_hash = "pbkdf2_sha256$1000$saltsalt$hashedvalue=="
        with patch.object(analyzer, "_read_password_db", return_value=[pbkdf2_hash]):
            result = analyzer.check_pbkdf2_iterations()
        assert result.status == TestStatus.FAIL

    def test_skip_when_no_pbkdf2(self, analyzer):
        """PBKDF2 해시가 없으면 SKIP이어야 한다."""
        with patch.object(analyzer, "_read_password_db", return_value=[]):
            result = analyzer.check_pbkdf2_iterations()
        assert result.status == TestStatus.SKIP
