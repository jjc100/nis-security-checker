"""
유틸리티 - 암호화 헬퍼 모듈
해시 계산, 엔트로피 분석, 알고리즘 강도 판별 기능을 제공합니다.
"""

import hashlib
import math
import re
from pathlib import Path


# 금지 암호 알고리즘 키워드
WEAK_ALGORITHMS = {
    "DES", "3DES", "RC2", "RC4", "RC5", "MD2", "MD4", "MD5",
    "SHA1", "SHA-1",
}

# 강력한 암호 알고리즘 키워드
STRONG_ALGORITHMS = {
    "AES", "AES-128", "AES-256", "CHACHA20",
    "SHA256", "SHA-256", "SHA384", "SHA-384", "SHA512", "SHA-512",
    "BCRYPT", "PBKDF2", "ARGON2", "SCRYPT",
}

# 패스워드 해시 패턴
HASH_PATTERNS = {
    "bcrypt": re.compile(r"\$2[ayb]\$\d{2}\$.{53}"),
    "pbkdf2_sha256": re.compile(r"pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+"),
    "argon2": re.compile(r"\$argon2(id|i|d)\$"),
    "sha512_crypt": re.compile(r"\$6\$(?:rounds=\d+\$)?[A-Za-z0-9./]+\$[A-Za-z0-9./]+"),
    "sha256_crypt": re.compile(r"\$5\$(?:rounds=\d+\$)?[A-Za-z0-9./]+\$[A-Za-z0-9./]+"),
    "md5_crypt": re.compile(r"\$1\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+"),
    "des_crypt": re.compile(r"^[A-Za-z0-9./]{13}$"),
    "ntlm": re.compile(r"^[0-9a-fA-F]{32}$"),
}


def sha256_file(path: str | Path) -> str:
    """
    파일의 SHA-256 해시를 계산합니다.

    Args:
        path: 파일 경로

    Returns:
        16진수 SHA-256 해시 문자열
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """
    바이트 데이터의 SHA-256 해시를 계산합니다.

    Args:
        data: 입력 바이트 데이터

    Returns:
        16진수 SHA-256 해시 문자열
    """
    return hashlib.sha256(data).hexdigest()


def calculate_entropy(data: bytes) -> float:
    """
    Shannon 엔트로피를 계산합니다.

    Args:
        data: 입력 바이트 데이터

    Returns:
        엔트로피 값 (0.0 ~ 8.0)
    """
    if not data:
        return 0.0

    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)

    return entropy


def is_high_entropy(data: bytes, threshold: float = 7.0) -> bool:
    """
    데이터가 높은 엔트로피를 가지는지 확인합니다.
    암호화된 데이터나 무작위 키의 경우 엔트로피가 높습니다.

    Args:
        data: 입력 바이트 데이터
        threshold: 엔트로피 임계값

    Returns:
        높은 엔트로피 여부
    """
    return calculate_entropy(data) >= threshold


def identify_hash_format(hash_str: str) -> str | None:
    """
    패스워드 해시 포맷을 식별합니다.

    Args:
        hash_str: 해시 문자열

    Returns:
        식별된 해시 포맷 이름 또는 None
    """
    for fmt_name, pattern in HASH_PATTERNS.items():
        if pattern.search(hash_str):
            return fmt_name
    return None


def is_weak_algorithm(text: str) -> list[str]:
    """
    텍스트에서 금지 암호 알고리즘을 탐지합니다.

    Args:
        text: 검사할 텍스트

    Returns:
        발견된 금지 알고리즘 목록
    """
    found = []
    upper_text = text.upper()
    for algo in WEAK_ALGORITHMS:
        if algo in upper_text:
            found.append(algo)
    return found


def is_strong_hash(hash_format: str) -> bool:
    """
    해시 포맷이 강력한 알고리즘에 해당하는지 확인합니다.

    Args:
        hash_format: 해시 포맷 이름

    Returns:
        강력한 해시 여부
    """
    weak_formats = {"md5_crypt", "des_crypt", "ntlm"}
    return hash_format not in weak_formats
