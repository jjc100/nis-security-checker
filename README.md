# NIS 영상보안제품 보안요구사항 적합성 검사 도구

영상보안제품(NVR/DVR/VMS/IP카메라 등)이 한국 영상보안 인증 보안요구사항을 충족하는지 검증하는 통합 검사 도구입니다.

## 검증 방식

- **블랙박스 (BlackBox)**: 네트워크/API 기반 외부 검사
- **그레이박스 (GrayBox)**: 파일시스템/바이너리 직접 분석
- **체크리스트 (Checklist)**: 검사자 수동 확인 및 기록

## 상태

✅ 구현 완료

## 설치

```bash
pip install -r requirements.txt
```

## 사용법

```bash
# 전체 검사 실행 (블랙박스 + 그레이박스 + 체크리스트)
python -m src.main --config config/target_config.yaml --mode all

# 블랙박스 검사만 실행
python -m src.main --config config/target_config.yaml --mode blackbox

# 그레이박스 검사만 실행
python -m src.main --config config/target_config.yaml --mode graybox

# 체크리스트 검사만 실행
python -m src.main --config config/target_config.yaml --mode checklist

# JSON 포맷으로 출력
python -m src.main --config config/target_config.yaml --format json --output output/result.json

# HTML 리포트 저장
python -m src.main --config config/target_config.yaml --format html --output output/report.html
```

## 아키텍처

```
nis-security-checker/
├── config/
│   ├── target_config.yaml       # 대상 호스트/포트/계정 설정
│   ├── checklist_items.yaml     # 55개 검사 항목 정의
│   └── requirements_map.yaml    # 항목↔요구사항 매핑
├── src/
│   ├── main.py                  # CLI 진입점 (argparse)
│   ├── runner.py                # 검사 오케스트레이터
│   ├── models.py                # 공통 데이터 모델 (TestResult, TestStatus)
│   ├── engines/
│   │   ├── blackbox/            # 외부 네트워크 검사 엔진 (8개 모듈)
│   │   ├── graybox/             # 파일시스템/바이너리 분석 엔진 (9개 모듈)
│   │   └── checklist/           # 대화형 체크리스트 엔진 (3개 모듈)
│   ├── report/
│   │   ├── generator.py         # 결과 집계 및 리포트 생성
│   │   ├── formatters.py        # JSON/HTML 저장
│   │   └── templates/report.html
│   └── utils/
│       ├── network.py           # 네트워크 유틸리티
│       ├── crypto.py            # 암호화 유틸리티
│       └── logger.py            # 로깅 설정
├── tests/                       # pytest 기반 단위 테스트 (48개)
└── docs/                        # 사용 가이드 및 요구사항 매핑 문서
```

### 검사 흐름

```
main.py (CLI)
  └─► runner.py (Runner)
        ├─► engines/blackbox/*   → TestResult[]
        ├─► engines/graybox/*    → TestResult[]
        ├─► engines/checklist/*  → TestResult[]
        └─► report/generator.py → JSON / HTML 리포트
```

## 검사 항목 (55개)

### 인증 (AUTH) — 8개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| AUTH-001 | 기본 계정 변경 강제 | blackbox | NIS 영상보안 2.1.1 |
| AUTH-002 | 유추 가능 계정명 금지 | checklist | NIS 영상보안 2.1.2 |
| AUTH-003 | 로그인 5회 실패 시 잠금 | blackbox | NIS 영상보안 2.1.3 |
| AUTH-004 | 잠금 해제 대기시간 5분 이상 | blackbox | NIS 영상보안 2.1.4 |
| AUTH-005 | 동일 오류 메시지 반환 | blackbox | NIS 영상보안 2.1.5 |
| AUTH-006 | 세션 유효시간 10분 이하 | blackbox | NIS 영상보안 2.1.6 |
| AUTH-007 | RTSP 인증 요구 | blackbox | NIS 영상보안 2.1.7 |
| AUTH-008 | ONVIF 인증 요구 | blackbox | NIS 영상보안 2.1.8 |

### 접근통제 (AC) — 6개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| AC-001 | API 역할 기반 접근통제 | blackbox | NIS 영상보안 2.2.1 |
| AC-002 | 불필요 포트 차단 | blackbox | NIS 영상보안 2.2.2 |
| AC-003 | Telnet/FTP 비활성화 | blackbox | NIS 영상보안 2.2.3 |
| AC-004 | 관리자 IP 화이트리스트 | checklist | NIS 영상보안 2.2.4 |
| AC-005 | SSH 키 인증 전용 | blackbox | NIS 영상보안 2.2.5 |
| AC-006 | HTTP→HTTPS 강제 리다이렉트 | blackbox | NIS 영상보안 2.2.6 |

### 암호화 (CRYPT) — 8개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| CRYPT-001 | TLS 1.2 이상 사용 | blackbox | NIS 영상보안 2.3.1 |
| CRYPT-002 | 취약 TLS 버전 거부 | blackbox | NIS 영상보안 2.3.2 |
| CRYPT-003 | 안전 암호 스위트 사용 | blackbox | NIS 영상보안 2.3.3 |
| CRYPT-004 | 금지 암호 알고리즘 미사용 | graybox | NIS 영상보안 2.3.4 |
| CRYPT-005 | 안전 해시 알고리즘 사용 | graybox | NIS 영상보안 2.3.5 |
| CRYPT-006 | 솔트 적용 해시 저장 | graybox | NIS 영상보안 2.3.6 |
| CRYPT-007 | PBKDF2 반복 횟수 충족 | graybox | NIS 영상보안 2.3.7 |
| CRYPT-008 | 하드코딩 키 미존재 | graybox | NIS 영상보안 2.3.8 |

### 영상보안 (VIDEO) — 4개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| VIDEO-001 | 영상 스트림 암호화 | checklist | NIS 영상보안 2.4.1 |
| VIDEO-002 | I-frame 암호화 적용 | graybox | NIS 영상보안 2.4.2 |
| VIDEO-003 | 저장 영상 암호화 | checklist | NIS 영상보안 2.4.3 |
| VIDEO-004 | 영상 무결성 검증 | graybox | NIS 영상보안 2.4.4 |

### SSH — 3개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| SSH-001 | SSH 프로토콜 버전 2.0 사용 | blackbox | NIS 영상보안 2.5.1 |
| SSH-002 | SSH 루트 직접 로그인 금지 | blackbox | NIS 영상보안 2.5.2 |
| SSH-003 | SSH 안전 MAC/암호화 알고리즘 | blackbox | NIS 영상보안 2.5.3 |

### 로그 (LOG) — 5개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| LOG-001 | 감사 로그 기록 | graybox | NIS 영상보안 2.6.1 |
| LOG-002 | 로그인 실패 이벤트 기록 | graybox | NIS 영상보안 2.6.2 |
| LOG-003 | 로그 변조 방지 | graybox | NIS 영상보안 2.6.3 |
| LOG-004 | 로그 보존 기간 90일 이상 | checklist | NIS 영상보안 2.6.4 |
| LOG-005 | 원격 로그 전송 | checklist | NIS 영상보안 2.6.5 |

### 파일시스템 (FS) — 3개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| FS-001 | 파일시스템 평문 패스워드 미존재 | graybox | NIS 영상보안 2.7.1 |
| FS-002 | 설정 파일 권한 제한 | graybox | NIS 영상보안 2.7.2 |
| FS-003 | 임시 파일 자동 삭제 | checklist | NIS 영상보안 2.7.3 |

### 메모리보안 (MEM) — 2개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| MEM-001 | 메모리 내 평문 인증정보 미존재 | graybox | NIS 영상보안 2.8.1 |
| MEM-002 | 메모리 초기화 정책 | checklist | NIS 영상보안 2.8.2 |

### 소프트웨어 (SW) — 4개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| SW-001 | 알려진 CVE 취약점 미존재 | graybox | NIS 영상보안 2.9.1 |
| SW-002 | 펌웨어 서명 검증 | checklist | NIS 영상보안 2.9.2 |
| SW-003 | 자동 업데이트 비활성화 옵션 | checklist | NIS 영상보안 2.9.3 |
| SW-004 | 불필요 서비스/데몬 비활성화 | graybox | NIS 영상보안 2.9.4 |

### 네트워크 (NET) — 3개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| NET-001 | UPnP 비활성화 | blackbox | NIS 영상보안 2.10.1 |
| NET-002 | SNMP 기본 커뮤니티 문자열 변경 | blackbox | NIS 영상보안 2.10.2 |
| NET-003 | mDNS/Bonjour 비활성화 | checklist | NIS 영상보안 2.10.3 |

### 권한 (PRIV) — 3개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| PRIV-001 | 최소 권한 원칙 적용 | graybox | NIS 영상보안 2.11.1 |
| PRIV-002 | SUID/SGID 파일 최소화 | graybox | NIS 영상보안 2.11.2 |
| PRIV-003 | 불필요 계정 비활성화 | checklist | NIS 영상보안 2.11.3 |

### 물리보안 (PHY) — 2개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| PHY-001 | USB/직렬 포트 비활성화 | checklist | NIS 영상보안 2.12.1 |
| PHY-002 | 물리 접근 탐지 | checklist | NIS 영상보안 2.12.2 |

### 운영보안 (OPS) — 4개

| ID | 제목 | 방식 | 참조 |
|----|------|------|------|
| OPS-001 | 보안 패치 관리 정책 | checklist | NIS 영상보안 2.13.1 |
| OPS-002 | 취약점 공시 정책 | checklist | NIS 영상보안 2.13.2 |
| OPS-003 | 공장 초기화 시 데이터 완전 삭제 | checklist | NIS 영상보안 2.13.3 |
| OPS-004 | 보안 이벤트 대응 절차 | checklist | NIS 영상보안 2.13.4 |

## 설정

`config/target_config.yaml` 파일에서 대상 호스트, 포트, 계정 정보, 기능 플래그를 설정합니다.

```yaml
target:
  host: "192.168.1.100"
  https_port: 443
  rtsp_port: 554
  ssh_port: 22
  username: "admin"
  password: "password"

features:
  rtsp_enabled: true
  onvif_enabled: true
  ssh_enabled: true
```

## 테스트

```bash
python -m pytest tests/ -v
```
