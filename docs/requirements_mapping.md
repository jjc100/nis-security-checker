# 영상보안제품 보안요구사항 매핑 테이블

영상보안제품 보안요구사항 인증 기준과 검사 도구 항목 간의 매핑 테이블입니다.

## 매핑 테이블

| 항목 ID | 제목 | 카테고리 | 검사 방법 | NIS 기준 참조 | 관련 모듈 |
|--------|------|--------|---------|-------------|---------|
| AUTH-001 | 기본 계정 변경 강제 | 인증 | blackbox | NIS 영상보안 2.1.1 | `default_cred_checker.py` |
| AUTH-002 | 유추 가능 계정명 금지 | 인증 | checklist | NIS 영상보안 2.1.2 | `default_cred_checker.py` |
| AUTH-003 | 로그인 5회 실패 시 잠금 | 인증 | blackbox | NIS 영상보안 2.1.3 | `login_tester.py` |
| AUTH-004 | 잠금 해제 대기시간 5분 이상 | 인증 | blackbox | NIS 영상보안 2.1.4 | `login_tester.py` |
| AUTH-005 | 동일 오류 메시지 반환 | 인증 | blackbox | NIS 영상보안 2.1.5 | `login_tester.py` |
| AUTH-006 | 2단계 인증 지원 | 인증 | checklist | NIS 영상보안 2.1.6 | `interactive.py` |
| AUTH-007 | ONVIF 인증 필수 적용 | 인증 | blackbox | NIS 영상보안 2.1.7 | `protocol_auth.py` |
| AUTH-008 | RTSP 인증 필수 적용 | 인증 | blackbox | NIS 영상보안 2.1.8 | `protocol_auth.py` |
| AC-001 | 권한 분리 (관리자/사용자) | 접근제어 | blackbox | NIS 영상보안 2.2.1 | `api_auth_tester.py` |
| AC-002 | 인증 없는 API 접근 차단 | 접근제어 | blackbox | NIS 영상보안 2.2.2 | `api_auth_tester.py` |
| AC-003 | 세션 타임아웃 10분 | 접근제어 | blackbox | NIS 영상보안 2.2.3 | `session_tester.py` |
| AC-004 | 중복 세션 차단 | 접근제어 | blackbox | NIS 영상보안 2.2.4 | `session_tester.py` |
| AC-005 | 세션 토큰 고유성 | 접근제어 | blackbox | NIS 영상보안 2.2.5 | `session_tester.py` |
| AC-006 | 불필요 서비스 포트 차단 | 접근제어 | blackbox | NIS 영상보안 2.2.6 | `port_scanner.py` |
| CRYPT-001 | TLS 1.2 이상 사용 | 암호화 | blackbox | NIS 영상보안 2.3.1 | `tls_checker.py` |
| CRYPT-002 | 취약 TLS 버전 거부 | 암호화 | blackbox | NIS 영상보안 2.3.2 | `tls_checker.py` |
| CRYPT-003 | 강력한 암호 스위트 사용 | 암호화 | blackbox | NIS 영상보안 2.3.3 | `tls_checker.py` |
| CRYPT-004 | 금지 암호 알고리즘 미사용 | 암호화 | graybox | NIS 영상보안 2.3.4 | `crypto_analyzer.py` |
| CRYPT-005 | 패스워드 단방향 해시 저장 | 암호화 | graybox | NIS 영상보안 2.3.5 | `hash_analyzer.py` |
| CRYPT-006 | 솔트(Salt) 적용 | 암호화 | graybox | NIS 영상보안 2.3.6 | `hash_analyzer.py` |
| CRYPT-007 | PBKDF2 반복횟수 10,000회 이상 | 암호화 | graybox | NIS 영상보안 2.3.7 | `hash_analyzer.py` |
| CRYPT-008 | 하드코딩 암호키 미존재 | 암호화 | graybox | NIS 영상보안 2.3.8 | `hardcoded_key_scanner.py` |
| VIDEO-001 | 영상 I-frame 암호화 | 영상보안 | graybox | NIS 영상보안 2.4.1 | `iframe_checker.py` |
| VIDEO-002 | 영상 전송 암호화 | 영상보안 | checklist | NIS 영상보안 2.4.2 | `interactive.py` |
| VIDEO-003 | 영상 무결성 검증 | 영상보안 | checklist | NIS 영상보안 2.4.3 | `interactive.py` |
| VIDEO-004 | 오디오 암호화 (해당 시) | 영상보안 | checklist | NIS 영상보안 2.4.4 | `interactive.py` |
| SSH-001 | SSH 프로토콜 버전 2 사용 | SSH보안 | blackbox | NIS 영상보안 2.5.1 | `ssh_checker.py` |
| SSH-002 | SSH 루트 로그인 비활성화 | SSH보안 | checklist | NIS 영상보안 2.5.2 | `interactive.py` |
| SSH-003 | SSH 패스워드 인증 비활성화 | SSH보안 | checklist | NIS 영상보안 2.5.3 | `interactive.py` |
| LOG-001 | 로그인 성공/실패 이벤트 기록 | 감사로그 | graybox | NIS 영상보안 2.6.1 | `log_analyzer.py` |
| LOG-002 | 감사로그 필수 필드 포함 | 감사로그 | graybox | NIS 영상보안 2.6.2 | `log_analyzer.py` |
| LOG-003 | 감사로그 내 민감정보 미포함 | 감사로그 | graybox | NIS 영상보안 2.6.3 | `log_analyzer.py` |
| LOG-004 | 설정 변경 이벤트 기록 | 감사로그 | checklist | NIS 영상보안 2.6.4 | `interactive.py` |
| LOG-005 | 감사로그 변조 방지 | 감사로그 | checklist | NIS 영상보안 2.6.5 | `interactive.py` |
| FS-001 | 설정 파일 접근 권한 제한 | 파일시스템 | graybox | NIS 영상보안 2.7.1 | `filesystem_analyzer.py` |
| FS-002 | 평문 패스워드 설정 파일 저장 금지 | 파일시스템 | graybox | NIS 영상보안 2.7.2 | `filesystem_analyzer.py` |
| FS-003 | 임시 파일 자동 삭제 | 파일시스템 | checklist | NIS 영상보안 2.7.3 | `interactive.py` |
| MEM-001 | 메모리 내 평문 인증정보 미존재 | 메모리보안 | graybox | NIS 영상보안 2.8.1 | `memory_analyzer.py` |
| MEM-002 | 메모리 보호 기법 적용 | 메모리보안 | checklist | NIS 영상보안 2.8.2 | `interactive.py` |
| SW-001 | 알려진 CVE 취약점 미존재 | 소프트웨어보안 | graybox | NIS 영상보안 2.9.1 | `cve_scanner.py` |
| SW-002 | 펌웨어/소프트웨어 서명 검증 | 소프트웨어보안 | checklist | NIS 영상보안 2.9.2 | `interactive.py` |
| SW-003 | 파일 무결성 검증 | 소프트웨어보안 | graybox | NIS 영상보안 2.9.3 | `integrity_checker.py` |
| SW-004 | 안전한 업데이트 채널 | 소프트웨어보안 | checklist | NIS 영상보안 2.9.4 | `interactive.py` |
| NET-001 | 불필요한 프로토콜 비활성화 | 네트워크보안 | blackbox | NIS 영상보안 2.10.1 | `port_scanner.py` |
| NET-002 | RTSP Digest 인증 강도 | 네트워크보안 | blackbox | NIS 영상보안 2.10.2 | `protocol_auth.py` |
| NET-003 | 방화벽/ACL 적용 | 네트워크보안 | checklist | NIS 영상보안 2.10.3 | `interactive.py` |
| PRIV-001 | 영상 데이터 접근 로그 기록 | 개인정보보호 | checklist | NIS 영상보안 2.11.1 | `interactive.py` |
| PRIV-002 | 마스킹/프라이버시 존 지원 | 개인정보보호 | checklist | NIS 영상보안 2.11.2 | `interactive.py` |
| PRIV-003 | 영상 데이터 보존 기간 정책 | 개인정보보호 | checklist | NIS 영상보안 2.11.3 | `interactive.py` |
| PHY-001 | 물리적 포트 비활성화 | 물리보안 | checklist | NIS 영상보안 2.12.1 | `interactive.py` |
| PHY-002 | 물리적 접근 감사로그 | 물리보안 | checklist | NIS 영상보안 2.12.2 | `interactive.py` |
| OPS-001 | 보안 패치 정기 적용 정책 | 운영보안 | checklist | NIS 영상보안 2.13.1 | `interactive.py` |
| OPS-002 | 초기화 기능 지원 | 운영보안 | checklist | NIS 영상보안 2.13.2 | `interactive.py` |
| OPS-003 | 보안 설정 내보내기/가져오기 | 운영보안 | checklist | NIS 영상보안 2.13.3 | `interactive.py` |
| OPS-004 | 이상 행동 탐지 및 알람 | 운영보안 | checklist | NIS 영상보안 2.13.4 | `interactive.py` |

## 검사 방법 설명

| 방법 | 설명 |
|------|------|
| **blackbox** | 네트워크/API를 통해 외부에서 자동으로 검사 |
| **graybox** | 파일시스템, 바이너리, 로그 등 내부 데이터에 직접 접근하여 검사 |
| **checklist** | 검사자가 직접 확인하고 Pass/Fail을 입력 |

## 자동화 가능 항목 통계

| 엔진 | 항목 수 | 비율 |
|------|------:|------|
| blackbox (자동) | 15개 | 29% |
| graybox (자동) | 12개 | 23% |
| checklist (수동) | 25개 | 48% |
| **합계** | **52개** | 100% |
