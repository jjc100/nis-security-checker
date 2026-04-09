# 영상보안제품 보안요구사항 적합성 검사 도구 사용 가이드

## 목차

1. [개요](#1-개요)
2. [설치 방법](#2-설치-방법)
3. [설정 파일](#3-설정-파일)
4. [검사 실행](#4-검사-실행)
5. [검사 모드 상세](#5-검사-모드-상세)
6. [결과 리포트](#6-결과-리포트)
7. [자주 묻는 질문](#7-자주-묻는-질문)

---

## 1. 개요

NIS 영상보안제품 보안요구사항 적합성 검사 도구는 IP카메라, NVR, DVR, VMS 등 영상보안제품이 한국 NIS 영상보안 인증 보안요구사항을 충족하는지 자동으로 검증합니다.

### 검사 방식

| 방식 | 설명 |
|------|------|
| **블랙박스 (BlackBox)** | 네트워크로 외부에서 TLS, 인증, 포트 등을 자동 검사 |
| **그레이박스 (GrayBox)** | 파일시스템, 바이너리, 로그에 직접 접근하여 암호화·무결성 검사 |
| **체크리스트 (Checklist)** | 검사자가 대화형 CLI로 수동 항목을 확인 |

---

## 2. 설치 방법

### 요구 사항

- Python 3.10 이상
- pip 패키지 관리자

### 패키지 설치

```bash
# 저장소 클론
git clone https://github.com/jjc100/nis-security-checker.git
cd nis-security-checker

# 의존성 설치
pip install -r requirements.txt

# 또는 pyproject.toml 기반 설치
pip install -e .
```

---

## 3. 설정 파일

### 3.1 대상 설정 파일 (`config/target_config.yaml`)

검사 대상 시스템의 정보를 설정합니다.

```yaml
target:
  host: 192.168.1.100    # 검사 대상 IP
  ports:
    https: 443           # HTTPS 포트
    rtsp: 554            # RTSP 포트
    http: 80             # HTTP 포트
    ssh: 22              # SSH 포트

credentials:
  admin:
    username: admin
    password: "Admin@1234"

features:
  has_rtsp: true         # RTSP 기능 여부
  has_onvif: true        # ONVIF 기능 여부
  has_ssh: true          # SSH 기능 여부
  has_audio: false       # 오디오 기능 여부
  has_2fa: false         # 2단계 인증 기능 여부
```

### 3.2 체크리스트 파일 (`config/checklist_items.yaml`)

52개 보안 검증 항목이 정의되어 있으며, 필요에 따라 커스터마이징할 수 있습니다.

---

## 4. 검사 실행

### 기본 실행 (전체 검사)

```bash
python -m src.main --config config/target_config.yaml --mode all
```

### 블랙박스 검사만 실행

```bash
python -m src.main --config config/target_config.yaml --mode blackbox
```

### 그레이박스 검사만 실행 (root 권한 필요)

```bash
sudo python -m src.main --config config/target_config.yaml --mode graybox
```

### 체크리스트 검사만 실행

```bash
python -m src.main --config config/target_config.yaml --mode checklist
```

### JSON 형식 리포트 생성

```bash
python -m src.main \
    --config config/target_config.yaml \
    --mode all \
    --output output/report.json \
    --format json
```

### 상세 로그 출력 및 로그 파일 저장

```bash
python -m src.main \
    --config config/target_config.yaml \
    --mode blackbox \
    --verbose \
    --log-file logs/checker.log
```

### 전체 옵션

```
옵션:
  --config 파일경로       대상 설정 YAML 파일 경로 (필수)
  --checklist 파일경로    체크리스트 항목 YAML 파일 경로
  --mode {blackbox,graybox,checklist,all}
                          검사 모드 (기본값: all)
  --output 파일경로       결과 출력 파일 경로
  --format {html,json}    출력 포맷 (기본값: html)
  --log-file 파일경로     로그 파일 경로
  --verbose, -v           상세 출력 모드
```

---

## 5. 검사 모드 상세

### 5.1 블랙박스 (BlackBox)

네트워크를 통해 외부에서 수행하는 자동 검사입니다.

| 모듈 | 검사 항목 |
|------|---------|
| `tls_checker.py` | TLS 1.2+ 사용, 취약 버전 거부, 암호 스위트 강도 |
| `protocol_auth.py` | RTSP/ONVIF 무인증 접근 차단, Digest 알고리즘 강도 |
| `login_tester.py` | 로그인 5회 실패 잠금, 동일 오류 메시지 반환 |
| `session_tester.py` | 세션 타임아웃 10분, 세션 토큰 고유성 |
| `port_scanner.py` | 불필요 서비스 포트 탐지, HTTP 비암호화 확인 |
| `ssh_checker.py` | SSH-2.0 프로토콜 사용 확인 |
| `api_auth_tester.py` | 무인증 API 접근 차단 확인 |
| `default_cred_checker.py` | 기본 계정(admin/admin 등) 로그인 시도 |

### 5.2 그레이박스 (GrayBox)

파일시스템, 바이너리, 로그에 직접 접근하는 검사입니다. **root 권한이 권장됩니다.**

| 모듈 | 검사 항목 |
|------|---------|
| `filesystem_analyzer.py` | 설정 파일 권한, 평문 패스워드 탐지 |
| `crypto_analyzer.py` | 바이너리 내 금지 암호 알고리즘 탐지 |
| `hash_analyzer.py` | 패스워드 해시 포맷, 솔트, PBKDF2 반복 횟수 |
| `hardcoded_key_scanner.py` | 하드코딩된 암호화 키 탐지 |
| `iframe_checker.py` | 영상 I-frame 암호화 여부 (엔트로피 분석) |
| `log_analyzer.py` | 감사로그 필수 이벤트/필드, 민감정보 미포함 |
| `memory_analyzer.py` | 프로세스 메모리 내 평문 인증정보 탐지 |
| `integrity_checker.py` | 파일 SHA-256 무결성 검증 |
| `cve_scanner.py` | NVD API를 통한 CVE 취약점 조회 |

### 5.3 체크리스트 (Checklist)

검사자가 직접 확인하고 입력하는 대화형 모드입니다.

- Rich CLI 인터페이스로 항목을 표시
- **P**(통과) / **F**(실패) / **N**(해당없음) / **M**(수동확인) 입력
- 비고 내용 입력 가능
- 증빙 파일 첨부 가능 (SHA-256 해시 자동 기록)
- 5개 항목마다 자동 저장

---

## 6. 결과 리포트

### 6.1 HTML 리포트

웹 브라우저에서 열 수 있는 대시보드 형식의 리포트입니다.

```bash
# HTML 리포트 생성 (기본)
python -m src.main --config config/target_config.yaml --output output/report.html
```

**포함 내용:**
- 전체 통과/실패/건너뜀/수동 통계 대시보드
- 통과율 진행 막대
- 카테고리별 상세 결과 테이블
- 각 항목의 ID, 이름, 상태, 엔진, 상세 내용

### 6.2 JSON 리포트

자동화 파이프라인이나 타 시스템 연동에 사용할 수 있는 JSON 형식 리포트입니다.

```bash
# JSON 리포트 생성
python -m src.main --config config/target_config.yaml --format json --output output/report.json
```

### 6.3 결과 상태 코드

| 상태 | 설명 |
|------|------|
| **PASS** | 보안 요구사항을 충족 |
| **FAIL** | 보안 요구사항 미충족 (개선 필요) |
| **SKIP** | 해당 기능이 없거나 조건에 해당하지 않아 건너뜀 |
| **MANUAL** | 자동 검사 불가, 수동 확인 필요 |
| **ERROR** | 검사 중 오류 발생 |

---

## 7. 자주 묻는 질문

### Q: 그레이박스 검사 시 권한 오류가 발생합니다.

A: 그레이박스 검사는 `/etc/shadow`, `/proc/<pid>/mem` 등 시스템 파일에 접근합니다. root 권한으로 실행하세요.

```bash
sudo python -m src.main --config config/target_config.yaml --mode graybox
```

### Q: CVE 검사가 느리거나 실패합니다.

A: NVD API는 API 키 없이 분당 5회로 제한됩니다. `config/target_config.yaml`에 NVD API 키를 설정하세요.

```yaml
nvd:
  api_key: "YOUR-NVD-API-KEY"
```

NVD API 키는 [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)에서 무료로 발급받을 수 있습니다.

### Q: 체크리스트 실행 중 실수로 종료됐습니다.

A: 5개 항목마다 `output/checklist_autosave.json`에 자동 저장됩니다. 이 파일을 확인하여 이전 결과를 참조하세요.

### Q: 무결성 검사(SW-003) 기준값을 어떻게 설정하나요?

A: 먼저 검사 도구를 실행하면 기준값이 없는 파일의 현재 해시가 MANUAL 결과에 출력됩니다. 해당 해시를 `config/target_config.yaml`의 `integrity_baseline`에 설정하세요.

```yaml
integrity_baseline:
  "/usr/sbin/nvrd": "abc123..."
  "/etc/nvr/config.conf": "def456..."
```

### Q: 특정 항목만 검사할 수 있나요?

A: 현재 버전에서는 모드 단위(blackbox/graybox/checklist)로 검사합니다. 개별 항목 선택 기능은 향후 버전에서 지원될 예정입니다.

### Q: 단위 테스트는 어떻게 실행하나요?

```bash
pip install pytest
pytest tests/ -v
```
