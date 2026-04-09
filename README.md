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
```

## 검사 항목

| 엔진 | 검사 항목 |
|------|----------|
| **블랙박스** | TLS 버전/암호스위트, RTSP/ONVIF 인증, 로그인 잠금, 세션 타임아웃, 포트스캔, SSH, API 권한, 기본계정 탐지 |
| **그레이박스** | 파일시스템 평문 패스워드, 금지 암호 알고리즘, 해시 분석, 하드코딩 키, I-frame 암호화, 감사로그, 메모리 분석, 무결성 검증, CVE 스캔 |
| **체크리스트** | Rich CLI 대화형 수동 확인 (Pass/Fail/N-A), 증빙 파일 첨부 |

## 설정

`config/target_config.yaml` 파일에서 대상 호스트, 포트, 계정 정보, 기능 플래그를 설정합니다.

## 테스트

```bash
python -m pytest tests/ -v
```