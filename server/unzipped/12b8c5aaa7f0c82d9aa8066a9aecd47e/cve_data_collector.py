"""
CVE Data Collector Tool for Vulnerability Scanner Agent

This module implements a tool for collecting vulnerability information from the CVE database.
It uses the NVD API to fetch CVE data and formats it for use by the vulnerability scanner agent.
"""

import requests
import time
import json
from typing import Dict, List, Optional, Union, Any
from google.adk.tools import LongRunningFunctionTool

# NVD API base URL
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class CVEDataCollector:
    """Class to handle CVE data collection from the NVD API."""
    
    def __init__(self):
        """Initialize the CVE data collector."""
        self.api_key = None  # Optional API key for higher rate limits
        self.delay = 6  # Default delay between requests (6 seconds for unauthenticated requests)
    
    def set_api_key(self, api_key: str) -> None:
        """
        Set the API key for NVD API access.
        
        Args:
            api_key: NVD API key for higher rate limits
        """
        self.api_key = api_key
        self.delay = 0.6  # Reduced delay for authenticated requests (0.6 seconds)
    
    def search_cve(self, 
                  cve_id: Optional[str] = None,
                  keywords: Optional[List[str]] = None,
                  published_start_date: Optional[str] = None,
                  published_end_date: Optional[str] = None,
                  last_modified_start_date: Optional[str] = None,
                  last_modified_end_date: Optional[str] = None,
                  cvss_v3_severity: Optional[str] = None,
                  max_results: int = 20) -> Dict[str, Any]:
        """
        Search for CVE data based on various criteria.
        
        Args:
            cve_id: Specific CVE ID to search for
            keywords: List of keywords to search for
            published_start_date: Start date for CVE publication (format: YYYY-MM-DD)
            published_end_date: End date for CVE publication (format: YYYY-MM-DD)
            last_modified_start_date: Start date for last modification (format: YYYY-MM-DD)
            last_modified_end_date: End date for last modification (format: YYYY-MM-DD)
            cvss_v3_severity: Filter by CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)
            max_results: Maximum number of results to return
            
        Returns:
            Dictionary containing CVE data
        """
        params = {}
        
        # Add search parameters
        if cve_id:
            params['cveId'] = cve_id
        
        if keywords:
            params['keywordSearch'] = ' '.join(keywords)
            
        if published_start_date:
            params['pubStartDate'] = f"{published_start_date}T00:00:00.000"
        
        if published_end_date:
            params['pubEndDate'] = f"{published_end_date}T23:59:59.999"
            
        if last_modified_start_date:
            params['lastModStartDate'] = f"{last_modified_start_date}T00:00:00.000"
            
        if last_modified_end_date:
            params['lastModEndDate'] = f"{last_modified_end_date}T23:59:59.999"
            
        if cvss_v3_severity:
            params['cvssV3Severity'] = cvss_v3_severity
        
        # Set result limits
        params['resultsPerPage'] = min(max_results, 2000)  # API max is 2000
        
        # Add API key if available
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        # Make the request
        try:
            response = requests.get(NVD_API_BASE_URL, params=params, headers=headers)
            response.raise_for_status()
            
            # Respect rate limiting
            time.sleep(self.delay)
            
            return self._process_cve_response(response.json())
            
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error_message": f"Error fetching CVE data: {str(e)}",
                "vulnerabilities": []
            }
    
    def _process_cve_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process the NVD API response and extract relevant CVE information.
        
        Args:
            response_data: Raw JSON response from the NVD API
            
        Returns:
            Processed CVE data in a structured format
        """
        result = {
            "status": "success",
            "total_results": response_data.get('totalResults', 0),
            "vulnerabilities": []
        }
        
        # Extract vulnerabilities
        for vuln in response_data.get('vulnerabilities', []):
            cve_item = vuln.get('cve', {})
            
            # Extract basic information
            cve_id = cve_item.get('id', '')
            description = self._get_description(cve_item)
            
            # Extract CVSS scores
            metrics = cve_item.get('metrics', {})
            cvss_v3 = self._extract_cvss_v3(metrics)
            cvss_v2 = self._extract_cvss_v2(metrics)
            
            # Extract references
            references = self._extract_references(cve_item)
            
            # Create structured vulnerability entry
            vulnerability = {
                "cve_id": cve_id,
                "description": description,
                "published": cve_item.get('published', ''),
                "last_modified": cve_item.get('lastModified', ''),
                "cvss_v3": cvss_v3,
                "cvss_v2": cvss_v2,
                "references": references
            }
            
            result["vulnerabilities"].append(vulnerability)
        
        return result
    
    def _get_description(self, cve_item: Dict[str, Any]) -> str:
        """Extract the English description from CVE item."""
        descriptions = cve_item.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        return ''
    
    def _extract_cvss_v3(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Extract CVSS v3 metrics if available."""
        cvss_v3_metrics = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
        
        if not cvss_v3_metrics:
            return {}
        
        # Use the first CVSS v3 entry
        cvss_data = cvss_v3_metrics[0].get('cvssData', {})
        
        return {
            "base_score": cvss_data.get('baseScore', 0),
            "severity": cvss_data.get('baseSeverity', ''),
            "vector_string": cvss_data.get('vectorString', ''),
            "exploitability_score": cvss_v3_metrics[0].get('exploitabilityScore', 0),
            "impact_score": cvss_v3_metrics[0].get('impactScore', 0)
        }
    
    def _extract_cvss_v2(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Extract CVSS v2 metrics if available."""
        cvss_v2_metrics = metrics.get('cvssMetricV2', [])
        
        if not cvss_v2_metrics:
            return {}
        
        # Use the first CVSS v2 entry
        cvss_data = cvss_v2_metrics[0].get('cvssData', {})
        
        return {
            "base_score": cvss_data.get('baseScore', 0),
            "severity": self._get_cvss_v2_severity(cvss_data.get('baseScore', 0)),
            "vector_string": cvss_data.get('vectorString', ''),
            "exploitability_score": cvss_v2_metrics[0].get('exploitabilityScore', 0),
            "impact_score": cvss_v2_metrics[0].get('impactScore', 0)
        }
    
    def _get_cvss_v2_severity(self, base_score: float) -> str:
        """Convert CVSS v2 base score to severity rating."""
        if base_score >= 7.0:
            return "HIGH"
        elif base_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _extract_references(self, cve_item: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract reference information from CVE item."""
        references = []
        
        for ref in cve_item.get('references', []):
            reference = {
                "url": ref.get('url', ''),
                "source": ref.get('source', ''),
                "tags": ref.get('tags', [])
            }
            references.append(reference)
        
        return references


def cve_data_collector(*args, **kwargs) -> Dict[str, Any]:
    """
    Generator function for collecting CVE data as a long-running function tool.
    
    Args:
        cve_id (str, optional): Specific CVE ID to search for
        keywords (list, optional): List of keywords to search for
        published_start_date (str, optional): Start date for CVE publication (format: YYYY-MM-DD)
        published_end_date (str, optional): End date for CVE publication (format: YYYY-MM-DD)
        cvss_v3_severity (str, optional): Filter by CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)
        max_results (int, optional): Maximum number of results to return (default: 20)
        api_key (str, optional): NVD API key for higher rate limits
        
    Yields:
        Progress updates during execution
        
    Returns:
        Dictionary containing CVE data
    """
    # Extract parameters
    cve_id = kwargs.get('cve_id')
    keywords = kwargs.get('keywords')
    published_start_date = kwargs.get('published_start_date')
    published_end_date = kwargs.get('published_end_date')
    cvss_v3_severity = kwargs.get('cvss_v3_severity')
    max_results = kwargs.get('max_results', 20)
    api_key = kwargs.get('api_key')
    
    # Initialize progress
    yield {
        "status": "pending",
        "message": "Initializing CVE data collection",
        "progress": 0
    }
    
    # Create collector
    collector = CVEDataCollector()
    
    # Set API key if provided
    if api_key:
        collector.set_api_key(api_key)
    
    # Update progress
    yield {
        "status": "pending",
        "message": "Connecting to NVD API",
        "progress": 25
    }
    
    # Perform search
    try:
        # Update progress
        yield {
            "status": "pending",
            "message": "Searching for vulnerabilities",
            "progress": 50
        }
        
        result = collector.search_cve(
            cve_id=cve_id,
            keywords=keywords,
            published_start_date=published_start_date,
            published_end_date=published_end_date,
            cvss_v3_severity=cvss_v3_severity,
            max_results=max_results
        )
        
        # Update progress
        yield {
            "status": "pending",
            "message": "Processing vulnerability data",
            "progress": 75
        }
        
        # Add summary information
        if result["status"] == "success":
            vuln_count = len(result["vulnerabilities"])
            high_severity_count = sum(1 for v in result["vulnerabilities"] 
                                    if v.get("cvss_v3", {}).get("severity") in ["HIGH", "CRITICAL"])
            
            result["summary"] = {
                "total_found": vuln_count,
                "high_severity_count": high_severity_count
            }
            
            message = f"Found {vuln_count} vulnerabilities ({high_severity_count} high severity)"
        else:
            message = "Error retrieving vulnerability data"
        
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
            "message": f"Error during CVE data collection: {str(e)}",
            "result": {
                "status": "error",
                "error_message": str(e),
                "vulnerabilities": []
            }
        }

# Create the tool
cve_tool = LongRunningFunctionTool(func=cve_data_collector)

# For testing
if __name__ == "__main__":
    # Test the collector directly
    collector = CVEDataCollector()
    result = collector.search_cve(keywords=["log4j"])
    print(json.dumps(result, indent=2))
    
    # Test the generator function
    generator = cve_data_collector(keywords=["log4j"])
    for update in generator:
        if isinstance(update, dict):
            print(f"Progress: {update.get('progress', 0)}% - {update.get('message', '')}")
        else:
            print("Final result:", update)
