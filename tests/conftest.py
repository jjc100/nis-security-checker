"""
공통 pytest fixture 모음
"""

import pytest


@pytest.fixture
def sample_config():
    """테스트용 대상 설정 픽스처"""
    return {
        "target": {
            "host": "127.0.0.1",
            "ports": {
                "https": 8443,
                "rtsp": 5540,
                "http": 8080,
                "ssh": 2222,
            },
        },
        "credentials": {
            "admin": {
                "username": "admin",
                "password": "Admin@1234",
            }
        },
        "features": {
            "has_audio": True,
            "has_2fa": False,
            "has_rtsp": True,
            "has_onvif": True,
            "has_ssh": True,
            "has_web_interface": True,
            "has_rest_api": True,
        },
        "max_login_attempts": 5,
        "nvd": {
            "api_key": "",
            "product_name": "",
            "vendor": "",
        },
        "default_credentials": [
            {"username": "admin", "password": "admin"},
            {"username": "root", "password": ""},
        ],
        "integrity_baseline": {},
    }


@pytest.fixture
def sample_checklist_items():
    """테스트용 체크리스트 항목 픽스처"""
    return [
        {
            "id": "AUTH-001",
            "category": "인증",
            "title": "기본 계정 변경 강제",
            "description": "기본 계정으로 로그인 불가 확인",
            "method": "checklist",
            "reference": "NIS 2.1.1",
            "condition": None,
        },
        {
            "id": "VIDEO-004",
            "category": "영상보안",
            "title": "오디오 암호화",
            "description": "오디오 데이터 암호화 여부 확인",
            "method": "checklist",
            "reference": "NIS 2.4.4",
            "condition": "has_audio",
        },
        {
            "id": "AUTH-006",
            "category": "인증",
            "title": "2단계 인증",
            "description": "2FA 지원 여부",
            "method": "checklist",
            "reference": "NIS 2.1.6",
            "condition": "has_2fa",
        },
    ]
