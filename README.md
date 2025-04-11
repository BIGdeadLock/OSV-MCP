
# MCP Server For OSV 

A lightweight MCP (Model Context Protocol) server for OSV Database API.

Example:

https://github.com/user-attachments/assets/55bb887f-3ead-4733-8328-572d3f3145fd

---

## Features

- **Get Package CVEs**: Fetch all CVEs related to a package.
- **Get CVE Affected Versions**: Fetch all the affected versions for a specific CVE-ID.
- **Get CVE Fix Versions**: Fetch all the versions that remediate the CVE.

---

## Prerequisites

1. **Python 3.11 or higher**: This project requires Python 3.11 or newer.
   ```bash
   # Check your Python version
   python --version
   ```

2. **Install uv**: A fast Python package installer and resolver.
   ```bash
   pip install uv
   ```
   Or use Homebrew:
   ```bash
   brew install uv
   ```

---

## Installation

Clone this repository:
```bash
git clone https://github.com/BIGdeadLock/OSV-MCP.git
cd src
```
---

## Configuration

For **Cursor** users:

```json
{
  "mcpServers": {
    "osv-mcp": {
      "command": "uv",
      "args": ["--directory", "/Users/eden.yavin/Projects/OSV-MCP", "run", "osv-server"],
      "env": {}
    }
  }
}

```
---

## Tools Provided

### Overview
|name|description|
|---|---|
|query_package_cve|List all the CVE IDs for a specific package. Specific version can be passed as well for more narrow scope CVE IDs.|
|query_for_cve_affected|Query the OSV database for a CVE and return all affected versions of the package.|
|query_for_cve_fix_versions|Query the OSV database for a CVE and return all versions that fix the vulnerability.|

### Detailed Description

- **query_package_cve**
  - Query the OSV database for a package and return the CVE IDs.
  - Input parameters:
    - `package` (string, required): The package name to query
    - `version` (string, optional): The version of the package to query. If not specified, queries all versions
    - `ecosystem` (string, optional): The ecosystem of the package. Defaults to "PyPI" for Python packages
  - Returns a list of CVE IDs with their details

- **query_for_cve_affected**
  - Query the OSV database for a CVE and return all affected versions.
  - Input parameters:
    - `cve` (string, required): The CVE ID to query (e.g., "CVE-2018-1000805")
  - Returns a list of affected version strings

- **query_for_cve_fix_versions**
  - Query the OSV database for a CVE and return all versions that fix the vulnerability.
  - Input parameters:
    - `cve` (string, required): The CVE ID to query (e.g., "CVE-2018-1000805")
  - Returns a list of fixed version strings

---
