from mcp.server.fastmcp import FastMCP
import requests, re

class OSVServer:

    def __init__(self):
        self.package_url = "https://api.osv.dev/v1/query"
        self.cve_url = "https://api.osv.dev/v1/vulns/OSV-{cve_id}"

    
    def _query_package(self, package: str, ecosystem: str, version: str = None):
        """
        Query the OSV database for a package.
        """
        data = {"package": {"name": package, "ecosystem": ecosystem}}
        if version:
            data['version'] = version

        response = requests.post(self.package_url, json=data)
        return response.json()

        
    def _query_cve(self, cve: str):
        """
        Query the OSV database for a CVE.
        """
        url = self.cve_url.format(cve_id=cve)
        response = requests.get(url)
        return response.json()

    def _parse_versions(self, data: dict):
        """
        Parse version strings from the OSV response.
        Extracts versions from the 'versions' array in the affected package data.
        
        Args:
            data: The full OSV response JSON data
            
        Returns:
            List of version strings
        """
        versions = []
        if 'affected' in data:
            for affected in data['affected']:
                if 'versions' in affected:
                    versions.extend(affected['versions'])
                    versions = list(set(versions))
        return versions

    def _parse_fix_versions(self, data: dict):
        """
        Parse fix version strings from the OSV response.
        Extracts fix versions from the 'ranges[].events[].fixed' in the affected package data.
        
        Args:
            data: The full OSV response JSON data
            
        Returns:
            List of fixed version strings
        """
        fix_versions = []
        if 'affected' in data:
            for affected in data['affected']:
                if 'ranges' in affected:
                    for range_data in affected['ranges']:
                        if 'events' in range_data:
                            for event in range_data['events']:
                                if 'fixed' in event:
                                    fix_versions.append(event['fixed'])
        return list(set(fix_versions))  # Remove duplicates

    def query_package_cve(self, package: str, ecosystem: str = "PyPI", version: str = None):
        """
        Query the OSV database for a package and return the CWE ID.
        """
        data = self._query_package(package, ecosystem, version)
        cves = []
        for vuln in data['vulns']:
            cve_id = re.search(r'CVE-(\d+)-(\d+)', str(vuln))
            if cve_id:
                cves.append({cve_id.group(0): vuln['details']})
        return cves
    
    def query_for_cve_affected(self, cve: str):
        """
        Query the OSV database for a CVE and return the affected versions.
        """
        data = self._query_cve(cve)
        versions = self._parse_versions(data)
        return versions
    
    def query_for_cve_fix_versions(self, cve: str):
        """
        Query the OSV database for a CVE and return the fix versions.
        """
        data = self._query_cve(cve)
        versions = self._parse_fix_versions(data)
        return versions
    

# MCP Server
mcp = FastMCP("OSV Database API MCP Server")


@mcp.tool()
def query_package_cve(package: str, version: str = None, ecosystem: str = "PyPI"):
    """
    Query the OSV database for a package and return the CVE ID.

    Args:
        package: The package name to query
        version: The version of the package to query, can be None if you want to query all versions
        ecosystem: The ecosystem of the package to query, can be None if you want to query all ecosystems. 
        * Supported ecosystems:
         - For python packages, the ecosystem is "PyPI"
    Returns:
        A list of CVE IDs
    """
    osv = OSVServer()
    return osv.query_package_cve(package, ecosystem, version)


@mcp.tool()
def query_for_cve_affected(cve: str):
    """
    Query the OSV database for a CVE and return the affected versions.

    Args:
        cve: The CVE ID to query

    Returns:
        A list of affected versions
    """
    osv = OSVServer()
    return osv.query_for_cve_affected(cve)

@mcp.tool()
def query_for_cve_fix_versions(cve: str):
    """
    Query the OSV database for a CVE and return the fix versions.

    Args:
        cve: The CVE ID to query

    Returns:
        A list of fix versions
    """
    osv = OSVServer()
    return osv.query_for_cve_fix_versions(cve)


# Test
if __name__ == "__main__":
    print(query_package_cve("paramiko"))
    print(query_for_cve_affected("CVE-2018-1000805"))
    print(query_for_cve_fix_versions("CVE-2018-1000805"))
