"""
Description: Model benchmark — run each chosen provider/model against a labeled
    vulnerable target and score recall, precision, and token cost, so a user can
    compare models before committing to one. Driven by `phrak benchmark` and the
    `/benchmark` chat command.
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations

import copy
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .banner import BGREEN, CYAN, GREEN, GREY, RESET, WHITE, YELLOW, phrak_print
from .config import (
    ANTHROPIC_MODELS,
    GROK_MODELS,
    OPENAI_MODELS,
    LLMConfig,
    provider_defaults,
)

# Ground-truth labels + the target source both ship inside the package so an
# installed PHRAK can benchmark without the repo checkout.
_BENCH_DIR = Path(__file__).resolve().parent / "benchmarks"
_TARGETS_DIR = _BENCH_DIR / "targets"

# The fixed request every model gets. Deliberately open-ended: we want to measure
# what a model finds when asked to assess the app, not lead it to the answers.
DEFAULT_REQUEST = (
    "Perform a thorough security assessment of this application. Identify every "
    "vulnerability you can find, each with its file and line reference."
)

# Providers the benchmark can drive, and the model IDs it suggests for each.
PROVIDERS = ("ollama", "anthropic", "openai", "grok")
SUGGESTED_MODELS: dict[str, tuple[str, ...]] = {
    "anthropic": ANTHROPIC_MODELS,
    "openai": OPENAI_MODELS,
    "grok": GROK_MODELS,
    "ollama": ("qwen2.5-coder:7b",),
}


# --------------------------------------------------------------- ground truth
@dataclass
class Truth:
    """One vulnerability a competent reviewer will find in the target."""

    id: str
    title: str
    cwe: str
    file: str
    line: int | None
    severity: str
    keywords: list[str] = field(default_factory=list)


def load_ground_truth(name: str = "vuln_app") -> tuple[str, list[Truth]]:
    """The (target filename, labeled findings) for a named benchmark."""
    data = yaml.safe_load((_BENCH_DIR / f"{name}.yaml").read_text()) or {}
    truths = [
        Truth(
            id=str(f.get("id", "")),
            title=str(f.get("title", "")),
            cwe=str(f.get("cwe", "")),
            file=str(f.get("file", "")),
            line=f.get("line"),
            severity=str(f.get("severity", "")),
            keywords=[str(k).lower() for k in (f.get("keywords") or [])],
        )
        for f in data.get("findings", [])
    ]
    return str(data.get("target", "")), truths


def target_files() -> list[Path]:
    """The source file(s) copied into each model's throwaway workspace."""
    return [p for p in _TARGETS_DIR.iterdir() if p.is_file()]


# --------------------------------------------------------------------- scoring
@dataclass
class ScoreCard:
    tp: int
    fp: int
    fn: int
    n_findings: int

    @property
    def recall(self) -> float:
        total = self.tp + self.fn
        return self.tp / total if total else 0.0

    @property
    def precision(self) -> float:
        total = self.tp + self.fp
        return self.tp / total if total else 0.0

    @property
    def f1(self) -> float:
        r, p = self.recall, self.precision
        return 2 * p * r / (p + r) if (p + r) else 0.0


def _norm_cwe(value: str) -> str:
    """Canonicalise a CWE reference to ``CWE-<n>`` (accepts bare numbers too)."""
    v = str(value).strip().upper().replace(" ", "")
    if v.startswith("CWE-"):
        return v
    if v.startswith("CWE"):
        return "CWE-" + v[3:].lstrip("-")
    return f"CWE-{v}" if v.isdigit() else v


def _finding_cwes(finding) -> set[str]:
    return {_norm_cwe(c) for c in (getattr(finding, "cwe_ids", None) or []) if c}


def _finding_text(finding) -> str:
    return " ".join(
        str(getattr(finding, attr, "") or "")
        for attr in ("title", "category", "description", "impact")
    ).lower()


def _finding_basenames(finding) -> set[str]:
    names = {Path(p).name for p in (getattr(finding, "affected_files", None) or []) if p}
    for ev in getattr(finding, "evidence", None) or []:
        if getattr(ev, "path", ""):
            names.add(Path(ev.path).name)
    for tp in getattr(finding, "taint_paths", None) or []:
        for node in (getattr(tp, "source", None), getattr(tp, "sink", None)):
            if node and getattr(node, "path", ""):
                names.add(Path(node.path).name)
    return names


def _finding_lines(finding) -> list[int]:
    lines: list[int] = []
    for ev in getattr(finding, "evidence", None) or []:
        if getattr(ev, "start_line", None):
            lines.append(int(ev.start_line))
    for tp in getattr(finding, "taint_paths", None) or []:
        for node in (getattr(tp, "source", None), getattr(tp, "sink", None)):
            if node and getattr(node, "line", None):
                lines.append(int(node.line))
    return lines


def _matches(finding, truth: Truth) -> bool:
    """Does ``finding`` describe ``truth``?

    A CWE overlap is decisive on its own. Otherwise a keyword must hit the
    finding's text AND the finding must point at the truth's file — either alone
    is too loose (a keyword can appear in unrelated prose; a file match says
    nothing about which vuln).
    """
    if _norm_cwe(truth.cwe) in _finding_cwes(finding):
        return True
    text = _finding_text(finding)
    kw_hit = any(k in text for k in truth.keywords)
    file_hit = Path(truth.file).name in _finding_basenames(finding)
    return bool(kw_hit and file_hit)


def _line_distance(finding, truth: Truth) -> int:
    """Closeness of a finding to a truth's line, for tie-breaking candidates."""
    if truth.line is None:
        return 0
    lines = _finding_lines(finding)
    if not lines:
        return 10_000  # no line info sorts after any located finding
    return min(abs(ln - truth.line) for ln in lines)


def score(findings: list, truths: list[Truth]) -> ScoreCard:
    """Greedy one-to-one match of findings against ground truth.

    Each truth claims the closest still-unused finding that describes it (line
    proximity breaks ties). True positives are matched truths; unmatched truths
    are misses (recall), and findings that matched nothing are false positives
    (precision). Complete labels for the target are assumed — an unlisted real
    vuln a model reports counts against precision.
    """
    used: set[int] = set()
    tp = 0
    for truth in truths:
        candidates = [
            i for i, f in enumerate(findings) if i not in used and _matches(f, truth)
        ]
        if not candidates:
            continue
        best = min(candidates, key=lambda i: _line_distance(findings[i], truth))
        used.add(best)
        tp += 1
    fn = len(truths) - tp
    fp = len(findings) - len(used)
    return ScoreCard(tp=tp, fp=fp, fn=fn, n_findings=len(findings))


# ----------------------------------------------------------------- running
@dataclass
class ResultRow:
    provider: str
    model: str
    score: ScoreCard | None
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0
    elapsed: float = 0.0
    error: str = ""

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.model}"

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


def run_one(
    base_config,
    llm_cfg: LLMConfig,
    request: str = DEFAULT_REQUEST,
    gt_name: str = "vuln_app",
) -> ResultRow:
    """Benchmark a single model in an isolated throwaway workspace.

    The target is copied into a temp dir whose ``.phrack`` holds this run's
    findings alone — nothing lands in the caller's real workspace. Token spend is
    measured as the delta of the process-wide counter across the run, so the
    session's own running total (and ``/cost``) stays intact.
    """
    from .app import build_app
    from .runtime import usage_totals
    from .store import FindingStore

    _, truths = load_ground_truth(gt_name)
    tmp = Path(tempfile.mkdtemp(prefix="phrak-bench-"))
    try:
        for src in target_files():
            shutil.copy2(src, tmp / src.name)

        cfg = copy.deepcopy(base_config)
        cfg.llm = llm_cfg
        cfg.paths.workspace = str(tmp)
        # Measure the MODEL, not the deterministic scanners, and never spin up a
        # container from a benchmark.
        cfg.analyzers.opengrep = False
        cfg.analyzers.dependency_audit = False
        cfg.enable_verify = False
        cfg.agent_models = {}  # every agent uses the model under test

        before = usage_totals()
        t0 = time.monotonic()
        error = ""
        findings: list = []
        try:
            app = build_app(cfg)
            app.orchestrator.run(request)
            findings = [rec.as_finding() for rec in FindingStore(cfg).list()]
        except Exception as e:  # provider/auth/rate-limit — recorded, not raised
            error = str(e)
        elapsed = time.monotonic() - t0
        after = usage_totals()

        return ResultRow(
            provider=llm_cfg.provider,
            model=llm_cfg.model,
            score=None if error else score(findings, truths),
            input_tokens=after["input"] - before["input"],
            output_tokens=after["output"] - before["output"],
            calls=after["calls"] - before["calls"],
            elapsed=elapsed,
            error=error,
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_benchmark(
    app,
    llm_cfgs: list[LLMConfig],
    request: str = DEFAULT_REQUEST,
    gt_name: str = "vuln_app",
) -> list[ResultRow]:
    """Run every model sequentially and return rows ranked best-first.

    Sequential by design: the token counter is process-wide, so overlapping runs
    would cross-attribute spend. Each ``build_app`` repoints the process runtime
    at the temp workspace, so the live session's runtime/workspace is restored
    once at the end.
    """
    rows: list[ResultRow] = []
    for i, cfg in enumerate(llm_cfgs, 1):
        phrak_print(
            f"{GREY}[{i}/{len(llm_cfgs)}]{RESET} benchmarking "
            f"{BGREEN}{cfg.provider}:{cfg.model}{RESET} …"
        )
        row = run_one(app.config, cfg, request=request, gt_name=gt_name)
        if row.error:
            phrak_print(f"  {YELLOW}failed: {row.error}{RESET}")
        elif row.score is not None:
            phrak_print(
                f"  {GREEN}done{RESET} {GREY}· recall {row.score.recall:.0%} · "
                f"precision {row.score.precision:.0%} · "
                f"{row.total_tokens} tok{RESET}"
            )
        rows.append(row)

    # Restore the live session's runtime/workspace (each run_one repointed it).
    from .credentials import load_into_env
    from .runtime import init_runtime

    load_into_env(app.config)
    init_runtime(app.config)

    rows.sort(
        key=lambda r: (
            r.score.f1 if r.score else -1.0,
            r.score.recall if r.score else -1.0,
        ),
        reverse=True,
    )
    return rows


# ----------------------------------------------------------------- rendering
def render_table(rows: list[ResultRow], gt_name: str = "vuln_app") -> str:
    """A plain, aligned comparison table ranked best-first."""
    target, truths = load_ground_truth(gt_name)
    headers = [
        "model",
        "recall",
        "prec",
        "F1",
        "TP/FP/FN",
        "in-tok",
        "out-tok",
        "calls",
        "time",
    ]
    table_rows: list[list[str]] = []
    for r in rows:
        if r.error:
            table_rows.append(
                [r.label, "—", "—", "—", "error", str(r.input_tokens),
                 str(r.output_tokens), str(r.calls), _fmt_time(r.elapsed)]
            )
            continue
        s = r.score
        table_rows.append(
            [
                r.label,
                f"{s.recall:.0%}",
                f"{s.precision:.0%}",
                f"{s.f1:.2f}",
                f"{s.tp}/{s.fp}/{s.fn}",
                str(r.input_tokens),
                str(r.output_tokens),
                str(r.calls),
                _fmt_time(r.elapsed),
            ]
        )

    widths = [len(h) for h in headers]
    for tr in table_rows:
        for i, cell in enumerate(tr):
            widths[i] = max(widths[i], len(cell))

    def fmt(cells: list[str]) -> str:
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    out = [
        f"{BGREEN}benchmark{RESET} {GREY}· target {WHITE}{target}{RESET}{GREY} · "
        f"{len(truths)} labeled vuln(s) · deterministic analyzers off{RESET}",
        "",
        f"{WHITE}{fmt(headers)}{RESET}",
        GREY + "-" * (sum(widths) + 2 * (len(widths) - 1)) + RESET,
    ]
    out += [fmt(tr) for tr in table_rows]
    errs = [r for r in rows if r.error]
    if errs:
        out.append("")
        for r in errs:
            out.append(f"{YELLOW}! {r.label}: {r.error}{RESET}")
    return "\n".join(out)


def results_json(rows: list[ResultRow]) -> list[dict]:
    """Machine-readable rows for ``--json`` / scripting."""
    out: list[dict] = []
    for r in rows:
        d = {
            "provider": r.provider,
            "model": r.model,
            "input_tokens": r.input_tokens,
            "output_tokens": r.output_tokens,
            "total_tokens": r.total_tokens,
            "model_calls": r.calls,
            "elapsed_seconds": round(r.elapsed, 2),
            "error": r.error,
        }
        if r.score is not None:
            s = r.score
            d.update(
                recall=round(s.recall, 4),
                precision=round(s.precision, 4),
                f1=round(s.f1, 4),
                tp=s.tp,
                fp=s.fp,
                fn=s.fn,
                n_findings=s.n_findings,
            )
        out.append(d)
    return out


def _fmt_time(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(round(seconds)), 60)
    return f"{m}m{s:02d}s"


# ------------------------------------------------------- interactive selection
def collect_targets_interactive(workspace: str = ".") -> list[LLMConfig]:
    """Prompt for provider / model / API key, one model per loop, until done.

    Returns the chosen :class:`LLMConfig`s. For a cloud provider whose key isn't
    already in the environment or the workspace credentials file, prompt for it,
    export it for this process, and offer to persist it to ``.phrack/credentials``.
    Ctrl-C / EOF ends selection early with whatever's been chosen so far.
    """
    from . import credentials
    from .config import _ask, _ask_secret

    chosen: list[LLMConfig] = []
    print(
        f"\n  {GREEN}benchmark setup{RESET} {GREY}— add one or more models to "
        f"compare. Empty provider when done.{RESET}"
    )
    try:
        while True:
            n = len(chosen) + 1
            provider = _ask(
                f"\n  model {n} — provider ({'/'.join(PROVIDERS)})",
                "ollama" if not chosen else "",
            ).lower()
            if not provider:
                break
            if provider not in PROVIDERS:
                phrak_print(f"{YELLOW}unknown provider '{provider}'{RESET}")
                continue

            suggestions = SUGGESTED_MODELS.get(provider, ())
            hint = f" (e.g. {', '.join(suggestions)})" if suggestions else ""
            model = _ask(
                f"  model{hint}", suggestions[0] if suggestions else ""
            )
            if not model:
                phrak_print(f"{YELLOW}a model id is required{RESET}")
                continue

            if not _ensure_key(provider, workspace, _ask_secret, credentials):
                continue

            chosen.append(_llm_config(provider, model))
            phrak_print(f"  {GREEN}added{RESET} {BGREEN}{provider}:{model}{RESET}")
    except (EOFError, KeyboardInterrupt):
        print()

    return chosen


def _ensure_key(provider: str, workspace: str, ask_secret, credentials) -> bool:
    """Make sure a cloud provider has a usable key; True if good to go."""
    var = credentials.PROVIDER_ENV_VARS.get(provider)
    if not var:  # ollama — no key
        return True
    if os.environ.get(var) or credentials.get_key(workspace, provider):
        return True
    key = ask_secret(f"  {var} (input hidden)")
    if not key:
        phrak_print(f"{YELLOW}no key entered — skipping {provider}{RESET}")
        return False
    os.environ[var] = key  # available to this process immediately
    from .config import _ask

    if _ask("  save this key to .phrack/credentials? (y/N)", "n").lower() in (
        "y",
        "yes",
    ):
        path = credentials.set_key(workspace, provider, key)
        phrak_print(f"  {GREY}stored in {path}{RESET}")
    return True


def _llm_config(provider: str, model: str) -> LLMConfig:
    """A provider-appropriate LLMConfig for a benchmark target."""
    cfg = provider_defaults(provider)
    cfg.model = model
    return cfg
