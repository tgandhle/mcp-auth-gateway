"""Official MCP SDK client driven end to end through the gateway.

Usage: python e2e_client.py <gateway-mcp-url> <bearer-token>
Prints one OK/FAIL line per step; exit 0 only if every step succeeded.
"""
from __future__ import annotations

import sys
import traceback

import anyio

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def run(url: str, token: str) -> int:
    headers = {"Authorization": f"Bearer {token}"}
    step = "connect"
    try:
        async with streamablehttp_client(url, headers=headers) as (read, write, _):
            async with ClientSession(read, write) as session:
                step = "initialize"
                res = await session.initialize()
                print(f"OK initialize server={res.serverInfo.name}", flush=True)

                step = "tools/list"
                tools = await session.list_tools()
                print(f"OK tools/list tools={[t.name for t in tools.tools]}", flush=True)

                step = "tools/call"
                out = await session.call_tool("echo", {"text": "hello"})
                print(f"OK tools/call result={out.content[0].text}", flush=True)
        return 0
    except BaseException as exc:  # noqa: BLE001 - report anything, incl. ExceptionGroup
        print(f"FAIL step={step} exc={type(exc).__name__}: {exc}", flush=True)
        print("".join(traceback.format_exception(exc, limit=3)), file=sys.stderr, flush=True)
        return 1


def main() -> None:
    url, token = sys.argv[1], sys.argv[2]
    raise SystemExit(anyio.run(run, url, token))


if __name__ == "__main__":
    main()