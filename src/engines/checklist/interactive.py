"""
체크리스트 엔진 - 대화형 체크리스트 모듈
Rich CLI를 사용한 대화형 체크리스트를 제공합니다.
검사자가 Pass/Fail/N-A를 직접 입력하고 증빙 파일을 첨부할 수 있습니다.
"""

import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from src.engines.checklist.evidence import EvidenceManager
from src.engines.checklist.items import filter_by_features, filter_by_method, group_by_category
from src.models import CheckItem, TestResult, TestStatus

# 결과 코드 → TestStatus 매핑
RESPONSE_MAP = {
    "p": TestStatus.PASS,
    "pass": TestStatus.PASS,
    "통과": TestStatus.PASS,
    "f": TestStatus.FAIL,
    "fail": TestStatus.FAIL,
    "실패": TestStatus.FAIL,
    "n": TestStatus.SKIP,
    "n/a": TestStatus.SKIP,
    "na": TestStatus.SKIP,
    "해당없음": TestStatus.SKIP,
    "s": TestStatus.SKIP,
    "skip": TestStatus.SKIP,
    "m": TestStatus.MANUAL,
    "manual": TestStatus.MANUAL,
}

# 자동 저장 파일 경로
AUTOSAVE_PATH = "output/checklist_autosave.json"


class InteractiveChecklist:
    """Rich CLI 대화형 체크리스트"""

    def __init__(
        self,
        items: list[dict],
        features: dict | None = None,
        evidence_dir: str = "output/evidence",
    ) -> None:
        self.raw_items = items
        self.features = features or {}
        self.console = Console()
        self.evidence_manager = EvidenceManager(evidence_dir)
        self._results: list[TestResult] = []

        # dict → CheckItem 변환
        self.check_items: list[CheckItem] = []
        for raw in items:
            self.check_items.append(CheckItem(
                id=raw.get("id", ""),
                category=raw.get("category", ""),
                title=raw.get("title", ""),
                description=raw.get("description", ""),
                method=raw.get("method", "checklist"),
                reference=raw.get("reference", ""),
                condition=raw.get("condition"),
            ))

    def _display_item(self, item: CheckItem, index: int, total: int) -> None:
        """체크리스트 항목을 화면에 표시합니다."""
        self.console.print(
            Panel(
                f"[bold cyan]{item.id}[/bold cyan] - {item.title}\n\n"
                f"[yellow]설명:[/yellow] {item.description}\n"
                f"[yellow]참조:[/yellow] {item.reference}",
                title=f"[{index}/{total}] {item.category}",
                border_style="blue",
            )
        )

    def _get_user_response(self) -> tuple[TestStatus, str]:
        """
        사용자 입력을 받아 (TestStatus, 비고) 를 반환합니다.

        Returns:
            (TestStatus, 비고 문자열)
        """
        self.console.print(
            "[bold]결과 입력:[/bold] "
            "[green]P(통과)[/green] / "
            "[red]F(실패)[/red] / "
            "[dim]N(해당없음)[/dim] / "
            "[yellow]M(수동확인)[/yellow]"
        )

        while True:
            response = Prompt.ask("결과").strip().lower()
            if response in RESPONSE_MAP:
                status = RESPONSE_MAP[response]
                break
            self.console.print("[red]잘못된 입력입니다. P/F/N/M 중 하나를 입력하세요.[/red]")

        comment = Prompt.ask("비고 (Enter 건너뜀)", default="")
        return status, comment

    def _ask_evidence(self, item_id: str) -> str | None:
        """증빙 파일 첨부 여부를 묻고 처리합니다."""
        attach = Prompt.ask("증빙 파일 첨부? (y/N)", default="n").strip().lower()
        if attach in ("y", "yes", "예"):
            file_path = Prompt.ask("파일 경로 입력").strip()
            try:
                stored = self.evidence_manager.attach(item_id, file_path)
                self.console.print(f"[green]✔ 증빙 파일 저장: {stored}[/green]")
                return stored
            except FileNotFoundError as e:
                self.console.print(f"[red]파일 오류: {e}[/red]")
        return None

    def _save_progress(self, results: list[TestResult]) -> None:
        """현재까지의 결과를 자동 저장합니다."""
        save_path = Path(AUTOSAVE_PATH)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        data = [r.to_dict() for r in results]
        save_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def _print_summary(self, results: list[TestResult]) -> None:
        """검사 결과 요약 테이블을 출력합니다."""
        table = Table(title="체크리스트 검사 결과 요약", show_header=True)
        table.add_column("상태", style="bold")
        table.add_column("건수", justify="right")

        status_counts: dict[str, int] = {}
        for r in results:
            status_counts[r.status.value] = status_counts.get(r.status.value, 0) + 1

        colors = {
            "PASS": "green",
            "FAIL": "red",
            "SKIP": "dim",
            "MANUAL": "yellow",
            "ERROR": "red bold",
        }

        for status_name, count in sorted(status_counts.items()):
            color = colors.get(status_name, "white")
            table.add_row(
                Text(status_name, style=color),
                str(count),
            )

        self.console.print(table)

    def run(self) -> list[TestResult]:
        """
        대화형 체크리스트를 실행합니다.

        Returns:
            검사 결과 목록
        """
        # 체크리스트 방법으로 필터링
        checklist_items = filter_by_method(self.check_items, "checklist")
        checklist_items = filter_by_features(checklist_items, self.features)

        if not checklist_items:
            self.console.print("[yellow]체크리스트 항목이 없습니다.[/yellow]")
            return []

        self.console.print(
            Panel(
                f"총 [bold]{len(checklist_items)}개[/bold]의 체크리스트 항목을 검사합니다.\n"
                "각 항목에 대해 P(통과), F(실패), N(해당없음), M(수동확인)을 입력하세요.",
                title="[bold blue]NIS 영상보안 체크리스트[/bold blue]",
                border_style="blue",
            )
        )

        results: list[TestResult] = []
        groups = group_by_category(checklist_items)

        item_index = 0
        total = len(checklist_items)

        for category, items in groups.items():
            self.console.rule(f"[bold blue]{category}[/bold blue]")

            for item in items:
                item_index += 1
                self._display_item(item, item_index, total)

                status, comment = self._get_user_response()
                evidence_path = self._ask_evidence(item.id)

                result = TestResult(
                    id=item.id,
                    name=item.title,
                    category=item.category,
                    status=status,
                    engine="checklist",
                    details=comment or f"검사자 직접 확인 ({status.value})",
                    timestamp=datetime.now(),
                    evidence_path=evidence_path,
                )
                results.append(result)

                # 5개 항목마다 자동 저장
                if item_index % 5 == 0:
                    self._save_progress(results)
                    self.console.print("[dim]진행 상황이 자동 저장되었습니다.[/dim]")

                self.console.print()

        self._save_progress(results)
        self._print_summary(results)
        return results
