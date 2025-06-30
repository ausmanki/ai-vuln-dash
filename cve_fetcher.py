import requests
import json
import time

NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY_SECONDS = 6  # NVD recommends not making more than 10 requests in a 60-second window without an API key. This is conservative.

def get_cve_details(cve_id: str) -> dict | None:
    """
    Fetches details for a given CVE ID from the NVD API.

    Args:
        cve_id: The CVE ID (e.g., "CVE-2019-1010218").

    Returns:
        A dictionary containing the CVE details if found, otherwise None.
    """
    url = f"{NVD_API_BASE_URL}?cveId={cve_id}"
    try:
        print(f"Fetching details for {cve_id} from {url}...")
        response = requests.get(url, timeout=10) # Added timeout
        response.raise_for_status()  # Raises an HTTPError for bad responses (4XX or 5XX)

        data = response.json()

        if data.get("vulnerabilities"):
            # Typically, a request by CVE ID returns one vulnerability.
            # We'll return the 'cve' item dictionary directly.
            return data["vulnerabilities"][0].get("cve")
        else:
            print(f"No vulnerability data found for {cve_id} in the response.")
            return None

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while fetching {cve_id}: {http_err}")
        if response.status_code == 404:
            print(f"CVE ID {cve_id} not found in NVD.")
        elif response.status_code == 403:
            print(f"Access forbidden. This might be due to API rate limiting. Response: {response.text}")
        else:
            print(f"Response content: {response.text}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred while fetching {cve_id}: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout occurred while fetching {cve_id}: {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"An unexpected error occurred while fetching {cve_id}: {req_err}")
    except json.JSONDecodeError:
        print(f"Failed to decode JSON response for {cve_id}.")

    return None

if __name__ == "__main__":
    sample_cve_ids = [
        "CVE-2019-1010218", # A known CVE
        "CVE-2021-44228",   # Log4Shell
        "CVE-1999-0001",    # An older CVE
        "CVE-2023-INVALID"  # An invalid/non-existent CVE
    ]

    for cve_id in sample_cve_ids:
        print(f"\n--- Testing with {cve_id} ---")
        details = get_cve_details(cve_id)
        if details:
            print(f"Successfully fetched details for {cve_id}:")
            # Print some basic info
            print(f"  ID: {details.get('id')}")
            print(f"  Published: {details.get('published')}")
            print(f"  Last Modified: {details.get('lastModified')}")
            if details.get('descriptions'):
                print(f"  Description (en): {next((d['value'] for d in details['descriptions'] if d['lang'] == 'en'), 'N/A')}")

            # Basic check for CVSS v3.x metrics
            if details.get('metrics', {}).get('cvssMetricV31'):
                cvss_v31 = details['metrics']['cvssMetricV31'][0]['cvssData']
                print(f"  CVSSv3.1 Score: {cvss_v31.get('baseScore')}, Severity: {cvss_v31.get('baseSeverity')}")
            elif details.get('metrics', {}).get('cvssMetricV30'):
                cvss_v30 = details['metrics']['cvssMetricV30'][0]['cvssData']
                print(f"  CVSSv3.0 Score: {cvss_v30.get('baseScore')}, Severity: {cvss_v30.get('baseSeverity')}")
            elif details.get('metrics', {}).get('cvssMetricV2'):
                cvss_v2 = details['metrics']['cvssMetricV2'][0]['cvssData']
                print(f"  CVSSv2 Score: {cvss_v2.get('baseScore')}, Severity: {details['metrics']['cvssMetricV2'][0].get('baseSeverity')}")
            else:
                print("  CVSS Metrics: Not available or not parsed in this example.")

        else:
            print(f"Failed to fetch details for {cve_id} or it was not found.")

        if cve_id != sample_cve_ids[-1]: # Don't sleep after the last one
            print(f"Waiting for {REQUEST_DELAY_SECONDS} seconds before next request...")
            time.sleep(REQUEST_DELAY_SECONDS)

    print("\n--- Test with a CVE that might be rate limited (example) ---")
    # This is just to show the rate limit handling, it might not trigger immediately
    # details = get_cve_details("CVE-2020-1472") # Zerologon
    # if details:
    #     print(f"Successfully fetched details for CVE-2020-1472")
    # else:
    #     print(f"Failed to fetch details for CVE-2020-1472 (might be due to rate limit or other error).")

    # Example of how to access references (patch info/advisories will be here)
    # log4shell_details = get_cve_details("CVE-2021-44228")
    # if log4shell_details and log4shell_details.get("references"):
    #     print("\n--- References for CVE-2021-44228 (Log4Shell) ---")
    #     for ref in log4shell_details["references"]:
    #         print(f"  URL: {ref.get('url')}")
    #         if ref.get('tags'):
    #             print(f"    Tags: {', '.join(ref.get('tags'))}")
