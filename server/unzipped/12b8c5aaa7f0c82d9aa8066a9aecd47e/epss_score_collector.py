"""
EPSS Score Collector Tool for Vulnerability Scanner Agent

This module implements a tool for collecting Exploit Prediction Scoring System (EPSS) scores.
EPSS provides a probability score indicating the likelihood that a vulnerability will be exploited.
"""

import requests
import time
import json
import csv
import io
from typing import Dict, List, Optional, Union, Any
from google.adk.tools import LongRunningFunctionTool

# EPSS API base URL
EPSS_API_BASE_URL = "https://api.first.org/data/v1/epss"

class EPSSScoreCollector:
    """Class to handle EPSS score collection."""
    
    def __init__(self):
        """Initialize the EPSS score collector."""
        self.delay = 1  # Default delay between requests (1 second)
        self.bulk_data_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    
    def get_score(self, cve_id: str) -> Dict[str, Any]:
        """
        Get EPSS score for a single CVE ID.
        
        Args:
            cve_id: The CVE ID to get the score for (e.g., CVE-2021-44228)
            
        Returns:
            Dictionary containing EPSS score data
        """
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
            
        params = {
            "cve": cve_id
        }
        
        try:
            response = requests.get(EPSS_API_BASE_URL, params=params)
            response.raise_for_status()
            
            # Respect rate limiting
            time.sleep(self.delay)
            
            return self._process_epss_response(response.json(), cve_id)
            
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error_message": f"Error fetching EPSS score: {str(e)}",
                "cve_id": cve_id,
                "epss_score": None,
                "percentile": None
            }
    
    def get_scores_batch(self, cve_ids: List[str]) -> Dict[str, Any]:
        """
        Get EPSS scores for multiple CVE IDs.
        
        Args:
            cve_ids: List of CVE IDs to get scores for
            
        Returns:
            Dictionary containing EPSS score data for multiple CVEs
        """
        result = {
            "status": "success",
            "scores": []
        }
        
        # Process in batches of 10 to avoid overwhelming the API
        batch_size = 10
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i+batch_size]
            
            for cve_id in batch:
                score_data = self.get_score(cve_id)
                if score_data.get("status") != "error":
                    result["scores"].append({
                        "cve_id": score_data.get("cve_id"),
                        "epss_score": score_data.get("epss_score"),
                        "percentile": score_data.get("percentile"),
                        "date": score_data.get("date")
                    })
                else:
                    result["scores"].append({
                        "cve_id": cve_id,
                        "epss_score": None,
                        "percentile": None,
                        "date": None,
                        "error": score_data.get("error_message")
                    })
        
        return result
    
    def download_bulk_data(self) -> Dict[str, Any]:
        """
        Download the complete EPSS dataset.
        This is useful for offline processing or when dealing with many CVEs.
        
        Returns:
            Dictionary containing the parsed EPSS dataset
        """
        try:
            response = requests.get(self.bulk_data_url)
            response.raise_for_status()
            
            # Parse the CSV data
            csv_data = csv.reader(io.StringIO(response.text))
            
            # Skip header row
            next(csv_data)
            
            epss_data = {}
            for row in csv_data:
                if len(row) >= 3:
                    cve_id = row[0]
                    epss_score = float(row[1])
                    percentile = float(row[2])
                    
                    epss_data[cve_id] = {
                        "epss_score": epss_score,
                        "percentile": percentile
                    }
            
            return {
                "status": "success",
                "data": epss_data,
                "count": len(epss_data)
            }
            
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "error_message": f"Error downloading EPSS bulk data: {str(e)}",
                "data": {},
                "count": 0
            }
    
    def _process_epss_response(self, response_data: Dict[str, Any], cve_id: str) -> Dict[str, Any]:
        """
        Process the EPSS API response and extract relevant score information.
        
        Args:
            response_data: Raw JSON response from the EPSS API
            cve_id: The CVE ID that was queried
            
        Returns:
            Processed EPSS score data in a structured format
        """
        if response_data.get("status") != "OK":
            return {
                "status": "error",
                "error_message": "EPSS API returned an error",
                "cve_id": cve_id,
                "epss_score": None,
                "percentile": None
            }
        
        data = response_data.get("data", [])
        if not data:
            return {
                "status": "not_found",
                "error_message": f"No EPSS data found for {cve_id}",
                "cve_id": cve_id,
                "epss_score": None,
                "percentile": None
            }
        
        # Extract the score data
        score_data = data[0]
        
        return {
            "status": "success",
            "cve_id": cve_id,
            "epss_score": score_data.get("epss"),
            "percentile": score_data.get("percentile"),
            "date": score_data.get("date")
        }


def epss_score_collector(*args, **kwargs) -> Dict[str, Any]:
    """
    Generator function for collecting EPSS scores as a long-running function tool.
    
    Args:
        cve_ids (list): List of CVE IDs to get scores for
        use_bulk_data (bool, optional): Whether to download the complete dataset (default: False)
        
    Yields:
        Progress updates during execution
        
    Returns:
        Dictionary containing EPSS score data
    """
    # Extract parameters
    cve_ids = kwargs.get('cve_ids', [])
    use_bulk_data = kwargs.get('use_bulk_data', False)
    
    # Initialize progress
    yield {
        "status": "pending",
        "message": "Initializing EPSS score collection",
        "progress": 0
    }
    
    # Create collector
    collector = EPSSScoreCollector()
    
    # Update progress
    yield {
        "status": "pending",
        "message": "Connecting to EPSS API",
        "progress": 25
    }
    
    # Perform collection
    try:
        if use_bulk_data:
            # Update progress
            yield {
                "status": "pending",
                "message": "Downloading complete EPSS dataset",
                "progress": 50
            }
            
            bulk_data = collector.download_bulk_data()
            
            if bulk_data["status"] == "success":
                # Filter for requested CVE IDs
                filtered_data = {
                    "status": "success",
                    "scores": []
                }
                
                for cve_id in cve_ids:
                    if not cve_id.startswith("CVE-"):
                        cve_id = f"CVE-{cve_id}"
                        
                    if cve_id in bulk_data["data"]:
                        score_info = bulk_data["data"][cve_id]
                        filtered_data["scores"].append({
                            "cve_id": cve_id,
                            "epss_score": score_info["epss_score"],
                            "percentile": score_info["percentile"]
                        })
                    else:
                        filtered_data["scores"].append({
                            "cve_id": cve_id,
                            "epss_score": None,
                            "percentile": None,
                            "error": "Not found in EPSS dataset"
                        })
                
                result = filtered_data
                
            else:
                result = {
                    "status": "error",
                    "error_message": bulk_data["error_message"],
                    "scores": []
                }
        else:
            # Update progress
            yield {
                "status": "pending",
                "message": f"Fetching EPSS scores for {len(cve_ids)} vulnerabilities",
                "progress": 50
            }
            
            result = collector.get_scores_batch(cve_ids)
        
        # Update progress
        yield {
            "status": "pending",
            "message": "Processing EPSS score data",
            "progress": 75
        }
        
        # Add summary information
        if result["status"] == "success":
            scores_count = len(result["scores"])
            high_risk_count = sum(1 for s in result["scores"] 
                                if s.get("epss_score") is not None and s.get("epss_score") > 0.5)
            
            result["summary"] = {
                "total_scores": scores_count,
                "high_risk_count": high_risk_count
            }
            
            message = f"Retrieved {scores_count} EPSS scores ({high_risk_count} high risk)"
        else:
            message = "Error retrieving EPSS score data"
        
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
            "message": f"Error during EPSS score collection: {str(e)}",
            "result": {
                "status": "error",
                "error_message": str(e),
                "scores": []
            }
        }

# Create the tool
epss_tool = LongRunningFunctionTool(func=epss_score_collector)

# For testing
if __name__ == "__main__":
    # Test the collector directly
    collector = EPSSScoreCollector()
    result = collector.get_score("CVE-2021-44228")
    print(json.dumps(result, indent=2))
    
    # Test batch collection
    batch_result = collector.get_scores_batch(["CVE-2021-44228", "CVE-2021-45046"])
    print(json.dumps(batch_result, indent=2))
    
    # Test the generator function
    generator = epss_score_collector(cve_ids=["CVE-2021-44228", "CVE-2021-45046"])
    for update in generator:
        if isinstance(update, dict):
            print(f"Progress: {update.get('progress', 0)}% - {update.get('message', '')}")
        else:
            print("Final result:", update)
