"""
데이터 모델 정의 모듈
검사 결과, 상태, 체크리스트 항목 등의 데이터 구조를 정의합니다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class TestStatus(Enum):
    """검사 결과 상태"""
    PASS = "PASS"       # 통과
    FAIL = "FAIL"       # 실패
    SKIP = "SKIP"       # 건너뜀
    MANUAL = "MANUAL"   # 수동 확인 필요
    ERROR = "ERROR"     # 오류 발생


@dataclass
class TestResult:
    """개별 검사 결과"""
    id: str                                     # 검사 항목 ID (예: AUTH-001)
    name: str                                   # 검사 항목 이름
    category: str                               # 카테고리 (예: 인증, 암호화)
    status: TestStatus                          # 검사 결과 상태
    engine: str                                 # 검사 엔진 (blackbox/graybox/checklist)
    details: str = ""                           # 상세 설명
    timestamp: datetime = field(default_factory=datetime.now)  # 검사 시각
    evidence_path: Optional[str] = None        # 증빙 파일 경로

    def to_dict(self) -> dict:
        """딕셔너리 변환"""
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "status": self.status.value,
            "engine": self.engine,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "evidence_path": self.evidence_path,
        }


@dataclass
class CheckItem:
    """체크리스트 항목"""
    id: str              # 항목 ID
    category: str        # 카테고리
    title: str           # 제목
    description: str     # 설명
    method: str          # 검사 방법 (blackbox/graybox/checklist)
    reference: str       # 관련 기준 참조
    condition: Optional[str] = None  # 적용 조건 (feature flag 이름)
