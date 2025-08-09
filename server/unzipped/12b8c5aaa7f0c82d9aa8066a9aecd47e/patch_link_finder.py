"""
Patch Link Finder Tool for Vulnerability Scanner Agent

This module implements a tool for finding patch links for vulnerabilities.
It searches vendor security advisories and other sources to locate remediation information.
"""

import requests
import time
import json
import re
from bs4 import BeautifulSoup
from typing import Dict, List, Optional, Union, Any
from google.adk.tools import LongRunningFunctionTool

class PatchLinkFinder:
    """Class to handle finding patch links for vulnerabilities."""
    
    def __init__(self):
        """Initialize the patch link finder."""
        self.delay = 1  # Default delay between requests (1 second)
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        
        # Common vendor security advisory URLs
        self.vendor_advisory_urls = {
            "microsoft": "https://msrc.microsoft.com/update-guide/vulnerability/",
            "cisco": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/",
            "oracle": "https://www.oracle.com/security-alerts/",
            "apache": "https://www.apache.org/security/",
            "redhat": "https://access.redhat.com/security/cve/",
            "ubuntu": "https://ubuntu.com/security/",
            "debian": "https://security-tracker.debian.org/tracker/",
            "ibm": "https://www.ibm.com/support/pages/security-bulletin-",
            "vmware": "https://www.vmware.com/security/advisories/",
            "sap": "https://wiki.scn.sap.com/wiki/display/PSE/",
        }
    
    def find_patch_links(self, cve_id: str, vendor: Optional[str] = None) -> Dict[str, Any]:
        """
        Find patch links for a specific vulnerability.
        
        Args:
            cve_id: The CVE ID to find patches for
            vendor: Optional vendor name to focus the search
            
        Returns:
            Dictionary containing patch information and links
        """
        # Ensure proper CVE ID format
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        
        result = {
            "status": "success",
            "cve_id": cve_id,
            "patch_links": [],
            "vendor_advisories": []
        }
        
        # Search for patch information from multiple sources
        try:
            # 1. Check NVD for references
            nvd_links = self._search_nvd(cve_id)
            if nvd_links:
                result["patch_links"].extend(nvd_links)
            
            # 2. Check vendor-specific advisories if vendor is specified
            if vendor:
                vendor_links = self._search_vendor_advisory(cve_id, vendor.lower())
                if vendor_links:
                    result["vendor_advisories"].extend(vendor_links)
            
            # 3. Check common security advisories
            advisory_links = self._search_common_advisories(cve_id)
            if advisory_links:
                result["vendor_advisories"].extend(advisory_links)
            
            # 4. Search for GitHub security advisories and commits
            github_links = self._search_github(cve_id)
            if github_links:
                result["patch_links"].extend(github_links)
            
            # Remove duplicates while preserving order
            result["patch_links"] = list(dict.fromkeys(result["patch_links"]))
            result["vendor_advisories"] = list(dict.fromkeys(result["vendor_advisories"]))
            
            return result
            
        except Exception as e:
            return {
                "status": "error",
                "error_message": f"Error finding patch links: {str(e)}",
                "cve_id": cve_id,
                "patch_links": [],
                "vendor_advisories": []
            }
    
    def _search_nvd(self, cve_id: str) -> List[str]:
        """Search NVD for patch links."""
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        
        try:
            headers = {"User-Agent": self.user_agent}
            response = requests.get(nvd_url, headers=headers)
            response.raise_for_status()
            
            # Respect rate limiting
            time.sleep(self.delay)
            
            # Parse the HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for references with patch tags
            patch_links = []
            reference_tables = soup.find_all("table", id=re.compile("vulnHyperlinksPanel"))
            
            for table in reference_tables:
                rows = table.find_all("tr")
                for row in rows:
                    # Check if this reference has a patch tag
                    tags = row.find_all("span", class_="badge")
                    is_patch = any("Patch" in tag.text for tag in tags)
                    
                    if is_patch:
                        link_element = row.find("a", href=True)
                        if link_element and link_element["href"]:
                            patch_links.append(link_element["href"])
            
            return patch_links
            
        except Exception as e:
            print(f"Error searching NVD: {str(e)}")
            return []
    
    def _search_vendor_advisory(self, cve_id: str, vendor: str) -> List[str]:
        """Search vendor-specific security advisories."""
        vendor_links = []
        
        # Check if we have a URL template for this vendor
        if vendor in self.vendor_advisory_urls:
            base_url = self.vendor_advisory_urls[vendor]
            
            # Handle vendor-specific URL patterns
            if vendor == "microsoft":
                advisory_url = f"{base_url}{cve_id}"
                vendor_links.append(advisory_url)
            elif vendor == "redhat":
                advisory_url = f"{base_url}{cve_id}"
                vendor_links.append(advisory_url)
            elif vendor == "cisco":
                # For Cisco, we would need to know the advisory ID
                # Just add the security advisories page
                vendor_links.append("https://tools.cisco.com/security/center/publicationListing.x")
            elif vendor == "oracle":
                # Oracle publishes quarterly CPU advisories
                vendor_links.append(f"{base_url}cpuapr2023.html")
                vendor_links.append(f"{base_url}cpujan2023.html")
                vendor_links.append(f"{base_url}cpuoct2022.html")
            elif vendor == "apache":
                # Apache has project-specific advisories
                vendor_links.append(f"{base_url}")
            else:
                # Generic case
                vendor_links.append(base_url)
        
        return vendor_links
    
    def _search_common_advisories(self, cve_id: str) -> List[str]:
        """Search common security advisory sources."""
        advisory_links = []
        
        # Add links to common security advisory sources
        advisory_links.append(f"https://www.kb.cert.org/vuls/byname?searchview&Query={cve_id}")
        advisory_links.append(f"https://security-tracker.debian.org/tracker/{cve_id}")
        advisory_links.append(f"https://ubuntu.com/security/{cve_id}")
        
        return advisory_links
    
    def _search_github(self, cve_id: str) -> List[str]:
        """Search GitHub for security advisories and patch commits."""
        github_links = []
        
        # Search GitHub security advisories
        github_advisory_url = f"https://github.com/advisories?query={cve_id}"
        github_links.append(github_advisory_url)
        
        # Search GitHub code for commits mentioning the CVE
        github_code_url = f"https://github.com/search?q={cve_id}+type:commit&type=code"
        github_links.append(github_code_url)
        
        return github_links
    
    def find_patch_links_batch(self, cve_ids: List[str], vendor: Optional[str] = None) -> Dict[str, Any]:
        """
        Find patch links for multiple vulnerabilities.
        
        Args:
            cve_ids: List of CVE IDs to find patches for
            vendor: Optional vendor name to focus the search
            
        Returns:
            Dictionary containing patch information for multiple vulnerabilities
        """
        result = {
            "status": "success",
            "results": []
        }
        
        # Process in batches of 5 to avoid overwhelming the sources
        batch_size = 5
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i+batch_size]
            
            for cve_id in batch:
                patch_result = self.find_patch_links(cve_id, vendor)
                result["results"].append(patch_result)
        
        return result


def patch_link_finder(*args, **kwargs) -> Dict[str, Any]:
    """
    Generator function for finding patch links as a long-running function tool.
    
    Args:
        cve_ids (list): List of CVE IDs to find patches for
        vendor (str, optional): Specific vendor to search for
        
    Yields:
        Progress updates during execution
        
    Returns:
        Dictionary containing patch information
    """
    # Extract parameters
    cve_ids = kwargs.get('cve_ids', [])
    vendor = kwargs.get('vendor')
    
    # Handle single CVE ID case
    if 'cve_id' in kwargs and kwargs['cve_id']:
        cve_ids = [kwargs['cve_id']]
    
    # Initialize progress
    yield {
        "status": "pending",
        "message": "Initializing patch link finder",
        "progress": 0
    }
    
    # Create finder
    finder = PatchLinkFinder()
    
    # Update progress
    yield {
        "status": "pending",
        "message": "Searching for patch information",
        "progress": 25
    }
    
    # Perform search
    try:
        if len(cve_ids) == 1:
            # Single CVE case
            cve_id = cve_ids[0]
            
            # Update progress
            yield {
                "status": "pending",
                "message": f"Searching for patch information for {cve_id}",
                "progress": 50
            }
            
            result = finder.find_patch_links(cve_id, vendor)
            
            # Update progress
            yield {
                "status": "pending",
                "message": "Processing patch information",
                "progress": 75
            }
            
            # Add summary information
            patch_count = len(result.get("patch_links", []))
            advisory_count = len(result.get("vendor_advisories", []))
            
            message = f"Found {patch_count} patch links and {advisory_count} vendor advisories for {cve_id}"
            
        else:
            # Multiple CVEs case
            # Update progress
            yield {
                "status": "pending",
                "message": f"Searching for patch information for {len(cve_ids)} vulnerabilities",
                "progress": 50
            }
            
            result = finder.find_patch_links_batch(cve_ids, vendor)
            
            # Update progress
            yield {
                "status": "pending",
                "message": "Processing patch information",
                "progress": 75
            }
            
            # Add summary information
            total_patches = sum(len(r.get("patch_links", [])) for r in result.get("results", []))
            total_advisories = sum(len(r.get("vendor_advisories", [])) for r in result.get("results", []))
            
            message = f"Found {total_patches} patch links and {total_advisories} vendor advisories for {len(cve_ids)} vulnerabilities"
        
        # Return final result
        return {
            "status": "completed",
            "message": message,
            "result": result
        }
        
    except Exception as e:
        # Handle any unexpected errors
        return {
            "status": "error",
            "message": f"Error during patch link finding: {str(e)}",
            "result": {
                "status": "error",
                "error_message": str(e),
                "results": []
            }
        }

# Create the tool
patch_tool = LongRunningFunctionTool(func=patch_link_finder)

# For testing
if __name__ == "__main__":
    # Test the finder directly
    finder = PatchLinkFinder()
    result = finder.find_patch_links("CVE-2021-44228")
    print(json.dumps(result, indent=2))
    
    # Test batch finding
    batch_result = finder.find_patch_links_batch(["CVE-2021-44228", "CVE-2021-45046"])
    print(json.dumps(batch_result, indent=2))
    
    # Test the generator function
    generator = patch_link_finder(cve_ids=["CVE-2021-44228"])
    for update in generator:
        if isinstance(update, dict):
            print(f"Progress: {update.get('progress', 0)}% - {update.get('message', '')}")
        else:
            print("Final result:", update)
