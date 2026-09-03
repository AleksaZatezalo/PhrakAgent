"""
Description: ReportWriter — persist per-agent & consolidated run reports under
    ``reports_dir`` and prune to ``keep_reports``.
Author: Aleksa Zatezalo
Date Created: 09-03-2026

The write side of reporting, split out of the Orchestrator (which plans and
executes). Where report files land, the shape they're written in, and how many
are kept is a self-contained concern — the companion to :mod:`appsec.report`,
which *assembles* the consolidated document's body.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .config import Config


class ReportWriter:
    """Writes run reports to ``config.reports_dir()`` and prunes old ones."""

    def __init__(self, config: Config) -> None:
        self.config = config

    @staticmethod
    def _ts() -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    # ------------------------------------------------------------- per-agent
    def save_agent_report(self, name: str, task: str, output: str) -> str:
        """Persist ONE agent's final output under ``reports_dir``; returns the path.

        A direct single-agent run (``phrak agent <name> ...``, ``/<name>`` in
        chat) skips the pipeline's consolidated report, so its output — including
        the structured findings the agent appends — would otherwise be lost once
        the terminal scrolls. The timestamp leads the filename so the shared
        ``report-*.md`` glob still sorts and prunes chronologically.
        """
        ts = self._ts()
        path = self.config.reports_dir() / f"report-{ts}-{name}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "\n".join(
                [
                    f"# {name} Report — {ts}",
                    f"\n**Agent:** {name}",
                    f"\n**Task:** {task}\n",
                    "## Output\n",
                    output,
                    "",
                ]
            )
        )
        self._prune()
        return str(path)

    def save_section_reports(self, tasks: list) -> None:
        """Save each completed threat_model / code_review task as its own report.

        generate_report quotes the latest ``report-<ts>-<agent>.md`` for those
        agents; a pipeline run only writes the consolidated report, so without
        this those sections show as 'no report found' placeholders even though
        the agents ran. Best-effort — a save failure never fails the run.
        """
        from .report import SECTION_AGENTS

        wanted = {a for a, _ in SECTION_AGENTS}
        for t in tasks:
            if t.agent not in wanted or t.status != "done":
                continue
            body = (t.artifact or "").strip()
            if not body or body.startswith("[task "):
                continue  # nothing usable (failed/skipped placeholder)
            try:
                self.save_agent_report(t.agent, t.task, t.artifact)
            except Exception as e:  # pragma: no cover - defensive
                from .banner import GREY, RESET

                print(f"  {GREY}(could not save {t.agent} report: {e}){RESET}")

    # ---------------------------------------------------------- consolidated
    def save_consolidated(
        self, request: str, plan: list, outputs: list[dict], report: str
    ) -> str:
        """Write the full pipeline report (plan + consolidated body + raw outputs)."""
        ts = self._ts()
        path = self.config.reports_dir() / f"report-{ts}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        body = [
            f"# AppSec Report — {ts}",
            f"\n**Request:** {request}\n",
            "## Plan",
            "\n".join(f"{i}. **{s.agent}** — {s.task}" for i, s in enumerate(plan, 1)),
            "\n## Consolidated Report\n",
            report,
            "\n---\n## Raw agent outputs\n",
        ]
        for o in outputs:
            body.append(f"### {o['agent']}\n\n{o['output']}\n")
        path.write_text("\n".join(body))
        self._prune()
        return str(path)

    # ----------------------------------------------------------------- prune
    def _prune(self) -> None:
        keep = self.config.keep_reports
        if not keep or keep <= 0:
            return
        d = self.config.reports_dir()
        files = sorted(d.glob("report-*.md"))
        for f in files[:-keep]:
            try:
                f.unlink()
            except OSError:
                pass
