"""
CLI 진입점 모듈
argparse를 사용한 명령행 인터페이스를 제공합니다.
"""

import argparse
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    """CLI 인자 파서를 구성하여 반환합니다."""
    parser = argparse.ArgumentParser(
        prog="nis-checker",
        description="영상보안제품 보안요구사항 적합성 검사 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  nis-checker --config config/target_config.yaml --mode all
  nis-checker --config config/target_config.yaml --mode blackbox --output result.html
  nis-checker --config config/target_config.yaml --mode checklist --format json
        """,
    )

    parser.add_argument(
        "--config",
        required=True,
        metavar="파일경로",
        help="대상 설정 YAML 파일 경로 (예: config/target_config.yaml)",
    )

    parser.add_argument(
        "--checklist",
        default="config/checklist_items.yaml",
        metavar="파일경로",
        help="체크리스트 항목 YAML 파일 경로 (기본값: config/checklist_items.yaml)",
    )

    parser.add_argument(
        "--mode",
        choices=["blackbox", "graybox", "checklist", "all"],
        default="all",
        help="검사 모드 (기본값: all)",
    )

    parser.add_argument(
        "--output",
        metavar="파일경로",
        help="결과 출력 파일 경로 (기본값: output/report.html 또는 output/report.json)",
    )

    parser.add_argument(
        "--format",
        choices=["html", "json"],
        default="html",
        help="출력 포맷 (기본값: html)",
    )

    parser.add_argument(
        "--log-file",
        metavar="파일경로",
        help="로그 파일 경로 (기본값: 없음, 콘솔만 출력)",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="상세 출력 모드",
    )

    return parser


def main() -> int:
    """메인 진입점. 반환값은 종료 코드."""
    parser = build_parser()
    args = parser.parse_args()

    # 설정 파일 존재 확인
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[오류] 설정 파일을 찾을 수 없습니다: {config_path}", file=sys.stderr)
        return 1

    checklist_path = Path(args.checklist)
    if not checklist_path.exists():
        print(f"[오류] 체크리스트 파일을 찾을 수 없습니다: {checklist_path}", file=sys.stderr)
        return 1

    # 출력 경로 기본값 설정
    if args.output is None:
        ext = "json" if args.format == "json" else "html"
        args.output = f"output/report.{ext}"

    # 출력 디렉토리 생성
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # runner 임포트 및 실행
    from src.runner import Runner  # 순환 임포트 방지를 위해 지연 임포트

    runner = Runner(
        config_path=str(config_path),
        checklist_path=str(checklist_path),
        mode=args.mode,
        output_path=str(output_path),
        output_format=args.format,
        log_file=args.log_file,
        verbose=args.verbose,
    )

    return runner.run()


if __name__ == "__main__":
    sys.exit(main())
