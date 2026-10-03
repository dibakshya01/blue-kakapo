"""The ``blue-kakapo`` / ``bk`` command-line entry point.

Commands: ``version``, ``info`` (redacted config), ``serve`` (run the API), ``triage`` (triage one
alert from a JSON file or stdin). Later stages add ``ollama bootstrap``, ``eval``, etc.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from . import __version__
from .config import get_settings
from .logging import configure_logging, get_logger


def _cmd_version(_: argparse.Namespace) -> int:
    print(f"blue-kakapo {__version__}")
    return 0


def _cmd_info(_: argparse.Namespace) -> int:
    s = get_settings()
    redacted = {
        "deployment_name": s.deployment_name,
        "default_tenant": s.default_tenant,
        "provider": s.provider.value,
        "model": s.model,
        "storage_backend": s.storage_backend.value,
        "memory_backend": s.memory_backend.value,
        "api": f"{s.api_host}:{s.api_port}",
        "offline": s.provider.value == "offline",
        "anthropic_key_set": bool(s.anthropic_api_key),
        "openai_key_set": bool(s.openai_api_key),
    }
    print("blue-kakapo configuration (secrets redacted):")
    for k, v in redacted.items():
        print(f"  {k}: {v}")
    return 0


_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", ""}


def _is_loopback(host: str) -> bool:
    return host.strip().lower() in _LOOPBACK_HOSTS


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    s = get_settings()
    configure_logging(level=s.log_level, json_logs=s.log_json)
    host = args.host or s.api_host
    # Refuse to expose an unauthenticated control plane on the network. With auth disabled every
    # request runs as local-admin, so a non-loopback bind would hand the SOC to anyone who can reach
    # the port. Enable auth (BK_AUTH_ENABLED=1) or, to override explicitly, --insecure / BK_ALLOW_INSECURE_BIND=1.
    if (
        not s.auth_enabled
        and not _is_loopback(host)
        and not (args.insecure or s.allow_insecure_bind)
    ):
        print(
            f"refusing to bind {host!r} with auth disabled — this would expose an unauthenticated "
            "admin API on the network.\n"
            "Fix one of:\n"
            "  • set BK_AUTH_ENABLED=1 (recommended) and configure tokens/OIDC, or\n"
            "  • bind loopback (127.0.0.1), or\n"
            "  • pass --insecure / set BK_ALLOW_INSECURE_BIND=1 if you truly intend this.",
            file=sys.stderr,
        )
        return 2
    get_logger("blue_kakapo.cli").info(
        "serving",
        host=host,
        port=args.port or s.api_port,
        provider=s.provider.value,
        auth_enabled=s.auth_enabled,
    )
    uvicorn.run(
        "blue_kakapo.api:create_app",
        factory=True,
        host=host,
        port=args.port or s.api_port,
        reload=args.reload,
    )
    return 0


def _cmd_triage(args: argparse.Namespace) -> int:
    from .agents import TriageOrchestrator
    from .core import Store
    from .providers import ProviderGateway

    s = get_settings()
    configure_logging(level=s.log_level, json_logs=s.log_json)
    if args.file == "-":
        raw_text = sys.stdin.read()
    else:
        with open(args.file, encoding="utf-8") as fh:
            raw_text = fh.read()
    alert = json.loads(raw_text)

    store = Store.from_settings(s)
    orch = TriageOrchestrator(store, ProviderGateway(s))
    case = asyncio.run(
        orch.triage_alert(alert, tenant_id=args.tenant or s.default_tenant, source=args.source)
    )
    v = case.verdict
    print(f"case:     {case.id}")
    print(f"title:    {case.title}")
    print(f"state:    {case.state}")
    if v:
        print(
            f"verdict:  {v.verdict_class}  (routing: {v.routing}, confidence: {v.confidence:.0%})"
        )
        print(f"rationale:{v.rationale}")
        print(f"evidence: {len(case.evidence)} item(s)")
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    from .eval import run_eval
    from .providers import ProviderGateway

    s = get_settings()
    report = asyncio.run(run_eval(dataset=args.dataset, gateway=ProviderGateway(s)))
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.render())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blue-kakapo", description="Open-source agentic SOC.")
    parser.add_argument("--version", action="version", version=f"blue-kakapo {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("version", help="Print the version.").set_defaults(func=_cmd_version)
    sub.add_parser("info", help="Show resolved config (redacted).").set_defaults(func=_cmd_info)

    serve = sub.add_parser("serve", help="Run the control-plane API.")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--reload", action="store_true")
    serve.add_argument(
        "--insecure",
        action="store_true",
        help="Allow a non-loopback bind with auth disabled (NOT recommended).",
    )
    serve.set_defaults(func=_cmd_serve)

    triage = sub.add_parser("triage", help="Triage one alert from a JSON file (or '-' for stdin).")
    triage.add_argument("file", help="Path to a JSON alert, or '-' to read stdin.")
    triage.add_argument("--tenant", default=None)
    triage.add_argument("--source", default="cli")
    triage.set_defaults(func=_cmd_triage)

    ev = sub.add_parser(
        "eval", help="Run the evaluation harness (reports the false-negative rate)."
    )
    ev.add_argument(
        "--dataset", default=None, help="Path to a labeled JSONL dataset (default: bundled)."
    )
    ev.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    ev.set_defaults(func=_cmd_eval)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
