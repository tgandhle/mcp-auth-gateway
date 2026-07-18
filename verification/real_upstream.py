"""A real MCP server (official SDK, Streamable HTTP) used as the gateway upstream."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "e2e-upstream",
    host="127.0.0.1",
    port=9000,
    stateless_http=True,
    json_response=True,
)


@mcp.tool()
def echo(text: str) -> str:
    """Echo the input back."""
    return f"echo: {text}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")