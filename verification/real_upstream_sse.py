"""Official SDK upstream using the default Streamable HTTP SSE response mode."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "e2e-upstream-sse",
    host="127.0.0.1",
    port=9002,
    stateless_http=True,
)


@mcp.tool()
def echo(text: str) -> str:
    """Echo the input back."""
    return f"echo: {text}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
