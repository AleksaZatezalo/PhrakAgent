"""
Description: RunRecorder — the capture half of an Agent run: turn a run's
    confirmed work into recorded, persisted, and rendered findings / test cases.
Author: Aleksa Zatezalo
Date Created: 09-03-2026

An :class:`~appsec.base_agent.Agent` drives the model turns; this collaborator
owns everything ABOUT the structured output of a run — which capture tools
exist, the prompts that nudge a model to record, how findings / test cases are
persisted to the durable stores and rendered into the report, and the
deterministic prose fallback for models that never call the capture tools.
Splitting it out keeps that knowledge in one place instead of threaded through
the run loop. The Agent still decides WHEN to run another turn; the recorder only
supplies the prompt for it and does the bookkeeping around it.
"""

from __future__ import annotations

from typing import Callable, Optional


class RunRecorder:
    """Captures, persists and renders one agent run's findings / test cases."""

    # Structured-capture tools. Unlike every other tool these write nothing to
    # the model's context and read nothing from disk — they only persist what the
    # model has already established — so they stay allowed after the exploration
    # budget is gone.
    RECORDING_TOOLS = ("report_finding", "report_test_case")

    def __init__(
        self,
        agent_name: str,
        config,
        tools: list,
        note: Callable[[str], None],
    ) -> None:
        self.agent_name = agent_name
        self.config = config
        self.note = note
        # Set by the Agent at the start of a run so persisted findings carry the
        # run they came from; "" is the right default for a direct capture call.
        self.run_id = ""
        self._names = [t.name for t in tools if t.name in self.RECORDING_TOOLS]

    # ------------------------------------------------------------- capability
    def tool_names(self) -> list[str]:
        """The recording tools this run actually has (e.g. threat_model has none)."""
        return list(self._names)

    def can_record(self) -> bool:
        return bool(self._names)

    def nothing_recorded(self) -> bool:
        """True while the run's collectors are still empty."""
        from .runtime import peek_findings, peek_test_cases

        return not (peek_findings() or peek_test_cases())

    # --------------------------------------------------------- prompt builders
    def reminder(self) -> str:
        """A nudge to record anything confirmed since the last capture call.

        Appended to mid-run continuation prompts. By this point the model is
        several rounds deep and drifting toward prose; without it, items it
        confirmed after its last capture call tend to reach only the report.
        """
        if not self._names:
            return ""
        listed = " / ".join(self._names)
        return (
            f" Before continuing, call {listed} for anything you have confirmed "
            "since your last one — items only described in prose are not "
            "recorded."
        )

    def writeup_prompt(self) -> Optional[str]:
        """The 'record what you confirmed before the tool-free write-up' prompt.

        None when the agent records nothing structured (e.g. threat_model), so
        the Agent skips straight to the write-up. Otherwise this is the one
        chance to persist confirmed items before the write-up round tells the
        model to stop calling tools — which silently includes the capture ones.
        """
        if not self._names:
            return None
        listed = " and ".join(f"`{n}`" for n in self._names)
        return (
            "Your exploration budget is spent. Do NOT read, search, or scan "
            "anything further — those tools will not run.\n\n"
            f"Before writing the report, RECORD your results: call {listed} "
            "once for each distinct item you have ALREADY confirmed by reading "
            "the code. These are the only tool calls you may make now.\n\n"
            "Anything you do not record here is absent from the operator's "
            "backlog even if you describe it in the prose report, so record "
            "every confirmed item, strongest first. Do not invent items you did "
            "not verify. When you are done, reply with the single word DONE."
        )

    def transcription_prompt(self, answer: str) -> Optional[str]:
        """Ask the model to transcribe a finished prose report into records.

        None (so the Agent skips the pass) when this agent can't record, when
        something is already recorded, or when there's no prose to transcribe.
        The fed-back report is capped to half the model's prompt budget so a
        long report plus the standing conversation doesn't overflow a small
        local context window.
        """
        if not self._names or not self.nothing_recorded():
            return None
        report = (answer or "").strip()
        if not report:
            return None
        from .llm import prompt_char_budget

        cap = max(2_000, prompt_char_budget(self.config.llm) // 2)
        if len(report) > cap:
            report = report[:cap] + "\n… [report truncated for the recording pass]"
        listed = " and ".join(f"`{n}`" for n in self._names)
        return (
            "Your written report is complete, but you have not RECORDED any of "
            "its items — so /findings and /testcases are still empty and the "
            "operator cannot track them. Do NOT read, search, or scan anything "
            "further.\n\n"
            f"Go through the report below and call {listed} once for EACH "
            "distinct item it describes, using the exact title, file/line, "
            "severity and other details already written there. These are the "
            "only tool calls you may make now. Record every item — an item only "
            "in prose does not exist for the operator. When done, reply DONE.\n\n"
            "--- REPORT ---\n" + report
        )

    # ------------------------------------------------------------ prose fallback
    def record_from_prose(self, answer: str) -> None:
        """Deterministically extract findings / test cases from the prose report.

        No model call, no tools — parses the text the agent already produced. The
        last line of defence for models that never emit capture calls at all.
        """
        from . import salvage
        from .runtime import record_finding, record_test_case

        res = salvage.parse_report(
            answer,
            source_agent=self.agent_name,
            findings="report_finding" in self._names,
            test_cases="report_test_case" in self._names,
        )
        n_f = sum(1 for f in res.findings if record_finding(f))
        n_t = sum(1 for tc in res.test_cases if record_test_case(tc))
        got = salvage.summary(n_f, n_t)
        if got:
            self.note(
                f"{self.agent_name}: recovered {got} from the report text "
                "(model did not record them)"
            )

    # --------------------------------------------------------------- finalize
    def finalize(self, answer: str) -> str:
        """Persist and append both the findings and test-case sections."""
        answer = self.append_findings(answer)
        answer = self.append_test_cases(answer)
        return answer

    def append_findings(self, answer: str) -> str:
        """Render any validated findings captured during the run into the report."""
        from .runtime import take_findings

        findings = take_findings()
        if not findings:
            # An agent that *can* record but didn't leaves /findings and
            # generate_report empty while the prose report is full of
            # vulnerabilities — say so, rather than letting the operator
            # discover it later and conclude nothing was found.
            if "report_finding" in self._names:
                self.note(
                    f"{self.agent_name}: no structured findings recorded — "
                    "/findings will be empty for this run"
                )
            return answer
        from .models.findings import dedupe_findings, severity_rank

        findings = dedupe_findings(findings)
        findings.sort(key=lambda f: (severity_rank(f.severity), -f.confidence))
        self.note(f"{self.agent_name}: recorded {len(findings)} structured finding(s)")
        self._persist_findings(findings)
        n_unconf = sum(1 for f in findings if f.status == "unconfirmed")
        n_grounded = len(findings) - n_unconf
        parts = [
            "",
            "---",
            "## Structured Findings (validated)",
            f"_{len(findings)} finding(s): {n_grounded} grounded, {n_unconf} "
            "unconfirmed. Evidence checked against the workspace._",
            "",
        ]
        for f in findings:
            parts.append(f.to_markdown())
            parts.append("")
        return answer + "\n".join(parts)

    def _persist_findings(self, findings: list) -> None:
        """Record this run's findings into the durable cross-run history store.

        Best-effort: history is a convenience layer, never allowed to fail a run
        — but a failure is *reported*, because the store is what ``/findings``
        triage reads, and silently dropping a run's findings looks identical to
        having found nothing.
        """
        try:
            from .store import FindingStore, TaintStore

            FindingStore(self.config).upsert(findings, run_id=self.run_id)
            TaintStore(self.config).upsert(findings, run_id=self.run_id)
        except Exception as e:
            self.note(f"could not write finding history: {e}")

    def append_test_cases(self, answer: str) -> str:
        """Persist any test cases authored this run and append them to the report."""
        from .runtime import take_test_cases

        cases = take_test_cases()
        if not cases:
            if "report_test_case" in self._names:
                self.note(
                    f"{self.agent_name}: no test cases recorded — "
                    "/testcases will be empty for this run"
                )
            return answer
        from .models.findings import severity_rank
        from .models.testcases import dedupe_test_cases

        cases = dedupe_test_cases(cases)
        cases.sort(key=lambda t: severity_rank(t.severity))
        self.note(f"{self.agent_name}: recorded {len(cases)} test case(s)")
        self._persist_test_cases(cases)
        parts = [
            "",
            "---",
            "## Test Cases (tracked)",
            f"_{len(cases)} test case(s) added to the backlog — track them with "
            "`/testcases`._",
            "",
        ]
        for tc in cases:
            parts.append(tc.to_markdown())
            parts.append("")
        return answer + "\n".join(parts)

    def _persist_test_cases(self, cases: list) -> None:
        """Merge authored test cases into the durable backlog (progress preserved)."""
        try:
            from .store import TestCaseStore

            TestCaseStore(self.config).upsert(cases)
        except Exception as e:
            self.note(f"could not write test-case backlog: {e}")
