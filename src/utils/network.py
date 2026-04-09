"""
유틸리티 - 네트워크 헬퍼 모듈
TCP 연결, SSL 컨텍스트, HTTP 요청 등의 네트워크 기능을 제공합니다.
"""

import socket
import ssl
from typing import Optional

import requests
import urllib3

# 자체 서명 인증서 경고 억제
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def tcp_connect(host: str, port: int, timeout: float = 5.0) -> bool:
    """
    TCP 연결 시도 후 성공 여부 반환.

    Args:
        host: 대상 호스트
        port: 대상 포트
        timeout: 연결 타임아웃 (초)

    Returns:
        연결 성공 여부
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def get_ssl_context() -> ssl.SSLContext:
    """
    TLS 1.2 이상으로 제한된 SSL 컨텍스트를 생성하여 반환합니다.

    Returns:
        설정된 SSLContext (최소 TLS 1.2)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_tls_info(host: str, port: int, timeout: float = 5.0) -> dict:
    """
    호스트의 TLS 연결 정보를 수집합니다.

    Args:
        host: 대상 호스트
        port: 대상 포트
        timeout: 연결 타임아웃

    Returns:
        TLS 정보 딕셔너리 (protocol, cipher, cert 등)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            return {
                "protocol": tls_sock.version(),
                "cipher": tls_sock.cipher(),
                "cert": tls_sock.getpeercert(),
            }


def http_get(
    url: str,
    headers: Optional[dict] = None,
    timeout: float = 10.0,
    verify_ssl: bool = False,
    **kwargs,
) -> requests.Response:
    """
    HTTP GET 요청을 수행합니다.

    Args:
        url: 요청 URL
        headers: 추가 헤더
        timeout: 요청 타임아웃
        verify_ssl: SSL 인증서 검증 여부

    Returns:
        HTTP 응답 객체
    """
    return requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl, **kwargs)


def http_post(
    url: str,
    data: Optional[dict | str] = None,
    json: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: float = 10.0,
    verify_ssl: bool = False,
    **kwargs,
) -> requests.Response:
    """
    HTTP POST 요청을 수행합니다.

    Args:
        url: 요청 URL
        data: 폼 데이터
        json: JSON 데이터
        headers: 추가 헤더
        timeout: 요청 타임아웃
        verify_ssl: SSL 인증서 검증 여부

    Returns:
        HTTP 응답 객체
    """
    return requests.post(
        url,
        data=data,
        json=json,
        headers=headers,
        timeout=timeout,
        verify=verify_ssl,
        **kwargs,
    )
