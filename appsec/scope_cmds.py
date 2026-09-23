"""
Description: `scope` command helpers — show and edit the workspace target-scope
    policy (.phrack/scope.yaml) without hand-editing YAML. Shared by `phrak scope`
    and `/scope`.
Author: Aleksa Zatezalo
Date Created: 09-22-2026
"""

from __future__ import annotations

import yaml

from .scope import ScopePolicy, SCOPE_FILENAME, load_policy, scope_path

_LOOPBACK = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def _split(text: str) -> list[str]:
    """Split a comma- or space-separated answer into a clean list."""
    return [x.strip() for x in (text or "").replace(",", " ").split() if x.strip()]


def _remote_hosts(hosts: list[str]) -> list[str]:
    return [h for h in hosts if h.lower() not in _LOOPBACK]


def _dedupe(existing: list, incoming) -> list:
    out = list(existing)
    for x in incoming or []:
        if x not in out:
            out.append(x)
    return out


def render_scope(config) -> str:
    """Show the current policy, or explain there isn't one yet."""
    p = scope_path(config)
    if not p.exists():
        return (
            f"no scope policy at {p}.\n"
            "Create one with `phrak scope --init`, then `--allow-host`, "
            "`--allow-port`, `--rate`, … to shape it (loopback-only still applies "
            "unless allow_remote_targets is set)."
        )
    policy = load_policy(config)
    body = yaml.safe_dump(policy.to_dict(), sort_keys=False).rstrip()
    lines = [f"# {p}", body]
    remote = [h for h in policy.allowed_hosts if h.lower() not in _LOOPBACK]
    if remote and not getattr(config, "allow_remote_targets", False):
        lines.append(
            f"\nnote: {', '.join(remote)} is a remote host — reaching it also "
            "needs `allow_remote_targets: true` in config."
        )
    return "\n".join(lines)


def edit_scope(
    config,
    *,
    init: bool = False,
    enable: bool = False,
    disable: bool = False,
    allow_hosts=None,
    remove_hosts=None,
    allow_ports=None,
    allow_paths=None,
    deny_paths=None,
    rate: int | None = None,
) -> str:
    """Apply edits to the scope policy and persist it. Returns the new policy."""
    p = scope_path(config)
    if init:
        policy = ScopePolicy(enabled=True, allowed_hosts=["127.0.0.1", "localhost"])
    elif p.exists():
        policy = load_policy(config)
    else:
        policy = ScopePolicy(enabled=True)  # a fresh, present file is enabled

    if enable:
        policy.enabled = True
    if disable:
        policy.enabled = False
    policy.allowed_hosts = _dedupe(
        policy.allowed_hosts, [h.lower() for h in (allow_hosts or [])]
    )
    if remove_hosts:
        drop = {h.lower() for h in remove_hosts}
        policy.allowed_hosts = [h for h in policy.allowed_hosts if h not in drop]
    policy.allowed_ports = _dedupe(policy.allowed_ports, allow_ports)
    policy.allowed_paths = _dedupe(policy.allowed_paths, allow_paths)
    policy.denied_paths = _dedupe(policy.denied_paths, deny_paths)
    if rate is not None:
        policy.rate_limit_per_min = max(0, int(rate))

    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(policy.to_dict(), sort_keys=False))
    return f"scope saved :: {p}\n\n" + render_scope(config)


def define_scope_interactive(config, config_path: str | None = None) -> str:
    """Prompt the user through defining the whole scope policy, then save it.

    Pre-fills from an existing policy. If a remote (non-loopback) host is added
    and the workspace hasn't opted into remote testing, offers to flip
    ``allow_remote_targets`` in config so the new scope is actually usable.
    """
    from .config import _ask

    existing = load_policy(config) if scope_path(config).exists() else None
    print("\n  define target scope (Enter keeps the shown default; Ctrl-C cancels)\n")
    try:
        enabled = _ask(
            "  enable policy? (Y/n)", "y" if (existing is None or existing.enabled) else "n"
        ).lower() not in ("n", "no")
        hosts = _split(
            _ask(
                "  allowed hosts (comma/space; blank = any loopback)",
                ", ".join(existing.allowed_hosts) if existing else "",
            )
        )
        ports_raw = _split(
            _ask(
                "  allowed ports (blank = any)",
                " ".join(str(x) for x in existing.allowed_ports) if existing else "",
            )
        )
        allow_paths = _split(
            _ask(
                "  allowed path prefixes (blank = any)",
                " ".join(existing.allowed_paths) if existing else "",
            )
        )
        deny_paths = _split(
            _ask(
                "  denied path prefixes (blank = none)",
                " ".join(existing.denied_paths) if existing else "",
            )
        )
        rate = int(
            _ask(
                "  rate limit per minute (0 = unlimited)",
                str(existing.rate_limit_per_min if existing else 0),
            )
            or 0
        )
    except (EOFError, KeyboardInterrupt):
        return "\ncancelled — scope not changed."

    ports: list[int] = []
    for x in ports_raw:
        try:
            ports.append(int(x))
        except ValueError:
            return f"invalid port: {x!r} — nothing saved."

    policy = ScopePolicy(
        enabled=enabled,
        allowed_hosts=[h.lower() for h in hosts],
        allowed_ports=ports,
        allowed_paths=allow_paths,
        denied_paths=deny_paths,
        rate_limit_per_min=max(0, rate),
    )
    p = scope_path(config)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(policy.to_dict(), sort_keys=False))

    extra = ""
    remote = _remote_hosts(policy.allowed_hosts)
    if remote and not getattr(config, "allow_remote_targets", False):
        try:
            ans = _ask(
                f"\n  {', '.join(remote)} is remote — enable allow_remote_targets "
                "for authorized testing? (y/N)",
                "n",
            )
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans.lower() in ("y", "yes"):
            config.allow_remote_targets = True
            from .config import default_config_path

            cpath = config_path or str(default_config_path(config.paths.workspace))
            try:
                config.save(cpath)
                extra = f"\nallow_remote_targets: true saved :: {cpath}"
            except Exception as e:
                extra = f"\n(could not save allow_remote_targets: {e})"

    return f"scope saved :: {p}\n\n" + render_scope(config) + extra


# Flags that mean "edit", so a bare invocation just shows the policy.
_EDIT_FLAGS = {
    "--init",
    "--enable",
    "--disable",
    "--allow-host",
    "--remove-host",
    "--allow-port",
    "--allow-path",
    "--deny-path",
    "--rate",
}


def parse_and_apply(config, tokens: list[str], config_path: str | None = None) -> str:
    """Chat entry point: bare `/scope` runs the interactive wizard; `--show`
    prints the policy; flags apply a non-interactive edit."""
    if not tokens:
        return define_scope_interactive(config, config_path=config_path)
    if len(tokens) == 1 and tokens[0] == "--show":
        return render_scope(config)
    if not any(t in _EDIT_FLAGS for t in tokens):
        return "usage: /scope [--init] [--allow-host H] [--allow-port P] "\
               "[--deny-path P] [--allow-path P] [--rate N] [--enable|--disable]"

    kwargs: dict = {
        "allow_hosts": [], "remove_hosts": [], "allow_ports": [],
        "allow_paths": [], "deny_paths": [],
    }
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t == "--init":
            kwargs["init"] = True
        elif t == "--enable":
            kwargs["enable"] = True
        elif t == "--disable":
            kwargs["disable"] = True
        elif t in ("--allow-host", "--remove-host", "--allow-port", "--allow-path",
                   "--deny-path", "--rate") and i + 1 < len(tokens):
            val = tokens[i + 1]
            i += 1
            if t == "--allow-host":
                kwargs["allow_hosts"].append(val)
            elif t == "--remove-host":
                kwargs["remove_hosts"].append(val)
            elif t == "--allow-port":
                try:
                    kwargs["allow_ports"].append(int(val))
                except ValueError:
                    return f"invalid port: {val!r}"
            elif t == "--allow-path":
                kwargs["allow_paths"].append(val)
            elif t == "--deny-path":
                kwargs["deny_paths"].append(val)
            elif t == "--rate":
                try:
                    kwargs["rate"] = int(val)
                except ValueError:
                    return f"invalid rate: {val!r}"
        else:
            return f"unknown or incomplete option: {t!r}"
        i += 1
    return edit_scope(config, **kwargs)
