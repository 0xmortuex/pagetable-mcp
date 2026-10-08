"""MCP stdio handshake smoke test: spawns the real server over stdio, checks
the tool list, and that instructive errors reach the client (MCPServer hides
any exception that isn't a ToolError behind "Error executing tool X")."""

import sys

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "pt_connect",
    "pt_disconnect",
    "pt_break",
    "pt_continue",
    "pt_interrupt",
    "pt_status",
    "pt_translate",
    "pt_explain_fault",
    "pt_map",
    "pt_find_phys",
    "pt_check",
}


@pytest.mark.anyio
async def test_tools_and_instructive_errors():
    params = StdioServerParameters(command=sys.executable, args=["-m", "pagetable_mcp"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "pagetable"
        names = {t.name for t in (await session.list_tools()).tools}
        assert names == EXPECTED_TOOLS, (
            f"missing: {EXPECTED_TOOLS - names}, unexpected: {names - EXPECTED_TOOLS}")

        result = await session.call_tool("pt_translate", {"name": "nope", "address": "0x1000"})
        assert result.is_error
        text = result.content[0].text
        assert "no session named 'nope'" in text and "call pt_connect first" in text

        result = await session.call_tool("pt_connect", {"name": "x", "elf": "missing.elf"})
        assert result.is_error and "ELF not found: missing.elf" in result.content[0].text


@pytest.fixture
def anyio_backend():
    return "asyncio"
