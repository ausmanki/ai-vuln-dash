"""
CISA KEV Data Collector Tool for Vulnerability Scanner Agent

This module implements a tool for collecting data from the CISA Known Exploited Vulnerabilities (KEV) catalog.
The KEV catalog contains vulnerabilities that are being actively exploited in the wild.
"""

import requests
import time
import json
import datetime
from typing import Dict, List, Optional, Union, Any
from google.adk.tools import LongRunningFunctionTool

# CISA KEV API base URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

class CISAKEVCollector:
    """Class to handle CISA KEV data collection."""
    
    def __init__(self):
        """Initialize the CISA KEV data collector."""
        self.delay = 1  # Default delay between requests (1 second)
        self.catalog_data = None
        self.last_update = None
    
    def fetch_catalog(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Fetch the complete CISA KEV catalog.
        
        Args:
            force_refresh: Whether to force a refresh of the catalog data
            
        Returns:
            Dictionary containing the KEV catalog data
        """
        # Check if we need to refresh the data
        current_time = datetime.datetime.now()
        if (not force_refresh and 
            self.catalog_data is not None and 
            self.last_update is not None and 
            (current_time - self.last_update).total_seconds() < 3600):
            # Use cached data if it's less than an hour old
            return {
                "status": "success",
                "catalog": self.catalog_data,
                "cached": True
            }
        
        try:
            response = requests.get(CISA_KEV_URL)
            response.raise_for_status()
            
            # Respect rate limiting
            time.sleep(self.delay)
            
            # Parse the JSON data
            catalog_data = response.json()
            
            # Cache the data
            self.catalog_data = catalog_data
            self.last_update = current_time
            
            return {
                "status": "success",
                "catalog": catalog_data,
                "cached": False
            }
            
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error_message": f"Error fetching CISA KEV catalog: {str(e)}",
                "catalog": None
            }
    
    def check_vulnerability(self, cve_id: str) -> Dict[str, Any]:
        """
        Check if a specific vulnerability is in the CISA KEV catalog.
        
        Args:
            cve_id: The CVE ID to check
            
        Returns:
            Dictionary containing KEV information for the vulnerability
        """
        # Ensure proper CVE ID format
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        
        # Fetch the catalog
        catalog_result = self.fetch_catalog()
        
        if catalog_result["status"] != "success":
            return {
                "status": "error",
                "error_message": catalog_result["error_message"],
                "cve_id": cve_id,
                "in_catalog": False,
                "kev_info": None
            }
        
        # Search for the CVE in the catalog
        catalog = catalog_result["catalog"]
        vulnerabilities = catalog.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            if vuln.get("cveID") == cve_id:
                return {
                    "status": "success",
                    "cve_id": cve_id,
                    "in_catalog": True,
                    "kev_info": {
                        "vendor_project": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                        "vulnerability_name": vuln.get("vulnerabilityName"),
                        "date_added": vuln.get("dateAdded"),
                        "short_description": vuln.get("shortDescription"),
                        "required_action": vuln.get("requiredAction"),
                        "due_date": vuln.get("dueDate"),
                        "notes": vuln.get("notes")
                    }
                }
        
        # CVE not found in the catalog
        return {
            "status": "success",
            "cve_id": cve_id,
            "in_catalog": False,
            "kev_info": None
        }
    
    def check_vulnerabilities_batch(self, cve_ids: List[str]) -> Dict[str, Any]:
        """
        Check if multiple vulnerabilities are in the CISA KEV catalog.
        
        Args:
            cve_ids: List of CVE IDs to check
            
        Returns:
            Dictionary containing KEV information for multiple vulnerabilities
        """
        result = {
            "status": "success",
            "vulnerabilities": []
        }
        
        # Fetch the catalog once
        catalog_result = self.fetch_catalog()
        
        if catalog_result["status"] != "success":
            return {
                "status": "error",
                "error_message": catalog_result["error_message"],
                "vulnerabilities": []
            }
        
        # Create a lookup dictionary for faster searching
        catalog = catalog_result["catalog"]
        vulnerabilities = catalog.get("vulnerabilities", [])
        kev_lookup = {}
        
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID")
            if cve_id:
                kev_lookup[cve_id] = vuln
        
        # Check each CVE ID
        for cve_id in cve_ids:
            # Ensure proper CVE ID format
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"
            
            if cve_id in kev_lookup:
                vuln = kev_lookup[cve_id]
                result["vulnerabilities"].append({
                    "cve_id": cve_id,
                    "in_catalog": True,
                    "kev_info": {
                        "vendor_project": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                        "vulnerability_name": vuln.get("vulnerabilityName"),
                        "date_added": vuln.get("dateAdded"),
                        "short_description": vuln.get("shortDescription"),
                        "required_action": vuln.get("requiredAction"),
                        "due_date": vuln.get("dueDate"),
                        "notes": vuln.get("notes")
                    }
                })
            else:
                result["vulnerabilities"].append({
                    "cve_id": cve_id,
                    "in_catalog": False,
                    "kev_info": None
                })
        
        return result
    
    def get_recent_additions(self, days: int = 30) -> Dict[str, Any]:
        """
        Get vulnerabilities recently added to the CISA KEV catalog.
        
        Args:
            days: Number of days to look back
            
        Returns:
            Dictionary containing recently added vulnerabilities
        """
        # Fetch the catalog
        catalog_result = self.fetch_catalog()
        
        if catalog_result["status"] != "success":
            return {
                "status": "error",
                "error_message": catalog_result["error_message"],
                "recent_additions": []
            }
        
        # Calculate the cutoff date
        cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
        
        # Filter for recent additions
        catalog = catalog_result["catalog"]
        vulnerabilities = catalog.get("vulnerabilities", [])
        
        recent_additions = []
        for vuln in vulnerabilities:
            date_added = vuln.get("dateAdded")
            if date_added and date_added >= cutoff_date:
                recent_additions.append({
                    "cve_id": vuln.get("cveID"),
                    "vendor_project": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "vulnerability_name": vuln.get("vulnerabilityName"),
                    "date_added": date_added,
                    "short_description": vuln.get("shortDescription"),
                    "required_action": vuln.get("requiredAction"),
                    "due_date": vuln.get("dueDate"),
                    "notes": vuln.get("notes")
                })
        
        return {
            "status": "success",
            "recent_additions": recent_additions,
            "count": len(recent_additions)
        }


def cisa_kev_collector(*args, **kwargs) -> Dict[str, Any]:
    """
    Generator function for collecting CISA KEV data as a long-running function tool.
    
    Args:
        cve_ids (list, optional): List of CVE IDs to check against the KEV catalog
        get_recent (bool, optional): Whether to get recent additions to the catalog
        recent_days (int, optional): Number of days to look back for recent additions
        force_refresh (bool, optional): Whether to force a refresh of the catalog data
        
    Yields:
        Progress updates during execution
        
    Returns:
        Dictionary containing CISA KEV data
    """
    # Extract parameters
    cve_ids = kwargs.get('cve_ids', [])
    get_recent = kwargs.get('get_recent', False)
    recent_days = kwargs.get('recent_days', 30)
    force_refresh = kwargs.get('force_refresh', False)
    
    # Initialize progress
    yield {
        "status": "pending",
        "message": "Initializing CISA KEV data collection",
        "progress": 0
    }
    
    # Create collector
    collector = CISAKEVCollector()
    
    # Update progress
    yield {
        "status": "pending",
        "message": "Fetching CISA KEV catalog",
        "progress": 25
    }
    
    # Perform collection
    try:
        # Fetch the catalog
        catalog_result = collector.fetch_catalog(force_refresh=force_refresh)
        
        if catalog_result["status"] != "success":
            return {
                "status": "error",
                "message": catalog_result["error_message"],
                "result": {
                    "status": "error",
                    "error_message": catalog_result["error_message"]
                }
            }
        
        # Update progress
        yield {
            "status": "pending",
            "message": "Processing KEV data",
            "progress": 50
        }
        
        result = {
            "status": "success",
            "catalog_info": {
                "title": catalog_result["catalog"].get("title"),
                "catalog_version": catalog_result["catalog"].get("catalogVersion"),
                "date_released": catalog_result["catalog"].get("dateReleased"),
                "count": len(catalog_result["catalog"].get("vulnerabilities", [])),
                "cached": catalog_result.get("cached", False)
            }
        }
        
        # Check specific CVE IDs if provided
        if cve_ids:
            # Update progress
            yield {
                "status": "pending",
                "message": f"Checking {len(cve_ids)} vulnerabilities against KEV catalog",
                "progress": 75
            }
            
            batch_result = collector.check_vulnerabilities_batch(cve_ids)
            result["vulnerabilities"] = batch_result["vulnerabilities"]
            
            # Count how many are in the catalog
            in_catalog_count = sum(1 for v in batch_result["vulnerabilities"] if v.get("in_catalog"))
            result["summary"] = {
                "total_checked": len(cve_ids),
                "in_catalog_count": in_catalog_count
            }
        
        # Get recent additions if requested
        if get_recent:
            # Update progress
            yield {
                "status": "pending",
                "message": f"Getting recent additions to KEV catalog (last {recent_days} days)",
                "progress": 75
            }
            
            recent_result = collector.get_recent_additions(days=recent_days)
            result["recent_additions"] = recent_result["recent_additions"]
            result["recent_count"] = recent_result["count"]
        
        # Determine message based on what was requested
        if cve_ids and get_recent:
            message = f"Found {in_catalog_count} vulnerabilities in KEV catalog and {result['recent_count']} recent additions"
        elif cve_ids:
            message = f"Found {in_catalog_count} vulnerabilities in KEV catalog"
        elif get_recent:
            message = f"Found {result['recent_count']} recent additions to KEV catalog"
        else:
            message = f"Successfully fetched KEV catalog with {result['catalog_info']['count']} vulnerabilities"
        
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
            "message": f"Error during CISA KEV data collection: {str(e)}",
            "result": {
                "status": "error",
                "error_message": str(e)
            }
        }

# Create the tool
kev_tool = LongRunningFunctionTool(func=cisa_kev_collector)

# For testing
if __name__ == "__main__":
    # Test the collector directly
    collector = CISAKEVCollector()
    
    # Test checking a single vulnerability
    result = collector.check_vulnerability("CVE-2021-44228")
    print(json.dumps(result, indent=2))
    
    # Test batch checking
    batch_result = collector.check_vulnerabilities_batch(["CVE-2021-44228", "CVE-2021-45046"])
    print(json.dumps(batch_result, indent=2))
    
    # Test getting recent additions
    recent_result = collector.get_recent_additions(days=30)
    print(f"Recent additions: {recent_result['count']}")
    
    # Test the generator function
    generator = cisa_kev_collector(cve_ids=["CVE-2021-44228", "CVE-2021-45046"], get_recent=True)
    for update in generator:
        if isinstance(update, dict):
            print(f"Progress: {update.get('progress', 0)}% - {update.get('message', '')}")
        else:
            print("Final result:", update)
