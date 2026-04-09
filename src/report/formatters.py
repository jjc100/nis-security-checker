"""
리포트 - 포맷 출력 모듈
JSON 및 HTML 포맷으로 리포트를 출력합니다.
"""

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def format_report(report_data: dict, output_path: str, fmt: str = "html") -> None:
    """
    리포트 데이터를 지정된 포맷으로 파일에 저장합니다.

    Args:
        report_data: 리포트 딕셔너리
        output_path: 출력 파일 경로
        fmt: 포맷 (html 또는 json)
    """
    if fmt == "json":
        _write_json(report_data, output_path)
    else:
        _write_html(report_data, output_path)


def _write_json(report_data: dict, output_path: str) -> None:
    """JSON 형식으로 리포트를 저장합니다."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report_data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _write_html(report_data: dict, output_path: str) -> None:
    """Jinja2 템플릿을 사용하여 HTML 리포트를 저장합니다."""
    # 템플릿 디렉토리 설정
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )

    template = env.get_template("report.html")
    html_content = template.render(**report_data)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html_content, encoding="utf-8")
