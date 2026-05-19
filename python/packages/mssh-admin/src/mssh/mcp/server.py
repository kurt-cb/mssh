"""mssh-mcp — MCP server, stdio transport.

Reads admin client config from ~/.mssh-admin/config (same as
mssh-admin uses) and exposes the read-only tool registry over MCP's
stdio transport. The intended use: register this server in Claude
Desktop / a local MCP client; ask read-only questions about the
mssh deployment in natural language.

Configuration: the same fields mssh-admin accepts via CLI flags or
config file:
  ca_url, admin_cert, admin_key, ca_cert.

Override the config path with --config (or env MSSH_ADMIN_CONFIG).

Status: v1 — read-only. Write tools (server_add, user_add, etc.)
are out of scope. See design/future-ideas.md §12 for the trust
model that would gate write access.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

import yaml

from mssh.admin.client import CAClient

from . import tools


log = logging.getLogger('mssh.mcp')


DEFAULT_CONFIG_PATH = Path.home() / '.mssh-admin' / 'config'


def _load_admin_config(path: Path) -> dict:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def _build_client(cfg: dict) -> CAClient | None:
    """Return a CAClient if the config has enough; else None.

    The MCP server starts either way — read-only tools that don't need
    the CA (like a future "explain how mssh works" tool) can still
    work, and `status` reports the missing-client gap as a check
    rather than crashing.
    """
    required = ('ca_url', 'admin_cert', 'admin_key', 'ca_cert')
    if not all(cfg.get(k) for k in required):
        log.warning('admin client config incomplete; CA-driven tools '
                    'will return an error. Missing: %s',
                    ', '.join(k for k in required if not cfg.get(k)))
        return None
    return CAClient(
        base_url=cfg['ca_url'],
        admin_cert=cfg['admin_cert'],
        admin_key=cfg['admin_key'],
        ca_cert=cfg['ca_cert'],
    )


async def _run_stdio(server, config_path: Path) -> None:
    """Start the MCP server on stdio."""
    from mcp.server.stdio import stdio_server
    async with stdio_server() as (read, write):
        await server.run(
            read, write,
            initialization_options=server.create_initialization_options(),
        )


def _make_mcp_server(client: CAClient | None, config_path: Path):
    """Build the MCP Server with handlers registered."""
    from mcp.server import Server
    import mcp.types as mcp_types

    app = Server('mssh-ca-mcp')

    @app.list_tools()
    async def list_tools():
        return [
            mcp_types.Tool(
                name=t['name'],
                description=t['description'],
                inputSchema=t['inputSchema'],
            )
            for t in tools.TOOL_REGISTRY
        ]

    @app.call_tool()
    async def call_tool(name: str, arguments: dict | None):
        t = tools.find_tool(name)
        if t is None:
            return [mcp_types.TextContent(
                type='text', text=f'Unknown tool: {name}')]
        args = dict(arguments or {})
        # Always inject the client; `status` accepts None.
        args['client'] = client
        # `status` also accepts a ca_dir from the config if available.
        # The other tools ignore extra kwargs not in their signatures,
        # so we filter to declared params before calling.
        import inspect
        sig = inspect.signature(t['fn'])
        accepted = set(sig.parameters)
        filtered = {k: v for k, v in args.items() if k in accepted}
        try:
            result = t['fn'](**filtered)
        except Exception as e:
            log.exception('tool %s raised', name)
            return [mcp_types.TextContent(
                type='text',
                text=f'Tool {name} raised: {type(e).__name__}: {e}')]
        return [mcp_types.TextContent(type='text', text=str(result))]

    return app


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog='mssh-mcp',
        description='Read-only MCP server for the mssh CA. '
                    'Exposes status, server_list, user_list, '
                    'user_inspect, audit_search, admin_list.',
    )
    p.add_argument('--config', default=os.environ.get('MSSH_ADMIN_CONFIG'),
                   help='Path to admin client config '
                        '(default: ~/.mssh-admin/config).')
    p.add_argument('--log-level', default='warning',
                   choices=['debug', 'info', 'warning', 'error'])
    args = p.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
        stream=sys.stderr,
    )

    config_path = Path(args.config) if args.config else DEFAULT_CONFIG_PATH
    cfg = _load_admin_config(config_path)
    client = _build_client(cfg)

    server = _make_mcp_server(client, config_path)
    try:
        asyncio.run(_run_stdio(server, config_path))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == '__main__':
    sys.exit(main())
