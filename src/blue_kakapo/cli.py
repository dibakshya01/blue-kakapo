"""The ``blue-kakapo`` / ``bk`` command-line entry point.

S0 commands: ``version``, ``info`` (show resolved config, redacted), ``serve`` (run the API).
Later stages add ``triage``, ``ollama bootstrap``, ``eval``, etc.
"""

from __future__ import annotations

import argparse
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


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    s = get_settings()
    configure_logging(level=s.log_level, json_logs=s.log_json)
    get_logger("blue_kakapo.cli").info(
        "serving",
        host=args.host or s.api_host,
        port=args.port or s.api_port,
        provider=s.provider.value,
    )
    uvicorn.run(
        "blue_kakapo.api:create_app",
        factory=True,
        host=args.host or s.api_host,
        port=args.port or s.api_port,
        reload=args.reload,
    )
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
    serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
