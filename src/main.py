from .server import mcp

def main():
    """Run the MCP server."""
    print("Starting OSV MCP server!")
    # Run the server
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main() 