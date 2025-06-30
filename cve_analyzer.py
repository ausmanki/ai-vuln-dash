import requests
import json
import time
from cve_fetcher import get_cve_details # Assuming cve_fetcher.py is in the same directory

EPSS_API_BASE_URL = "https://api.first.org/data/v1/epss"
REQUEST_DELAY_SECONDS_EPSS = 2 # EPSS API is generally faster, but good to be polite

# Patch Availability States
PATCH_AVAILABLE = "PATCH_AVAILABLE"
WORKAROUND_AVAILABLE = "WORKAROUND_AVAILABLE" # or Unclear
NO_PATCH_CONFIRMED = "NO_PATCH_CONFIRMED"
PATCH_STATUS_UNKNOWN = "PATCH_STATUS_UNKNOWN"

def get_epss_score(cve_id: str) -> tuple[float | None, float | None]:
    """
    Fetches the EPSS score and percentile for a given CVE ID.

    Args:
        cve_id: The CVE ID (e.g., "CVE-2022-27225").

    Returns:
        A tuple containing (epss_score, epss_percentile) if found, otherwise (None, None).
    """
    url = f"{EPSS_API_BASE_URL}?cve={cve_id}"
    try:
        # print(f"Fetching EPSS for {cve_id} from {url}...")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "OK" and data.get("data"):
            if data["data"]:
                epss_info = data["data"][0]
                return float(epss_info.get("epss")), float(epss_info.get("percentile"))
            else:
                # print(f"No EPSS data found for {cve_id} in the response, but status OK.")
                return None, None # CVE exists but no EPSS score
        elif data.get("status_code") == 404: # Check if this is how EPSS API indicates not found
            print(f"EPSS API returned 404 for {cve_id}. It might not exist in EPSS DB.")
            return None, None
        else:
            # print(f"EPSS data not found or error for {cve_id}. Status: {data.get('status_code')}, Message: {data.get('message')}")
            return None, None

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while fetching EPSS for {cve_id}: {http_err}")
        if response.status_code == 404 : # Explicitly check for 404 if API behaves this way
             print(f"CVE ID {cve_id} not found in EPSS database (404).")
        elif response.status_code == 429: # Rate limit
            print(f"Rate limited by EPSS API for {cve_id}. Try again later.")
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred while fetching EPSS for {cve_id}: {req_err}")
    except json.JSONDecodeError:
        print(f"Failed to decode JSON response for EPSS on {cve_id}.")
    except KeyError:
        print(f"Unexpected EPSS API response structure for {cve_id}.")

    return None, None

def check_patch_availability(references: list) -> str:
    """
    Heuristically determines patch availability from CVE references.
    This is a simplified heuristic.

    Args:
        references: A list of reference objects from NVD data.

    Returns:
        One of PATCH_AVAILABLE, WORKAROUND_AVAILABLE, NO_PATCH_CONFIRMED, PATCH_STATUS_UNKNOWN.
    """
    if not references:
        return PATCH_STATUS_UNKNOWN

    has_patch_tag = False
    has_vendor_advisory_tag = False
    has_third_party_advisory_tag = False

    patch_keywords = ["patch", "fix", "remediation", "security update", "bulletin"]
    no_patch_keywords = ["no patch", "will not fix", "no fix available", "unpatched"] # Less common in refs

    for ref in references:
        tags = ref.get("tags", [])
        url = ref.get("url", "").lower()

        if "Patch" in tags:
            has_patch_tag = True
        if "Vendor Advisory" in tags:
            has_vendor_advisory_tag = True
        if "Third Party Advisory" in tags: # Sometimes these point to solutions
            has_third_party_advisory_tag = True

        for keyword in patch_keywords:
            if keyword in url: # Simplistic check in URL
                # Could also use view_text_website here for more advanced check, but adds complexity & time
                has_patch_tag = True # Assume URL containing keyword implies patch info
                break

        for keyword in no_patch_keywords:
            if keyword in url: # Or if stated in description of ref (not available here directly)
                return NO_PATCH_CONFIRMED

    if has_patch_tag or has_vendor_advisory_tag:
        return PATCH_AVAILABLE
    if has_third_party_advisory_tag: # Less certain, but often leads to a solution
        return WORKAROUND_AVAILABLE # Could also be PATCH_AVAILABLE depending on strictness

    # Default if no strong signals
    return PATCH_STATUS_UNKNOWN


def calculate_risk_score(cve_id: str) -> dict | None:
    """
    Calculates the CVE Risk Profile Score.
    """
    print(f"\nAnalyzing CVE: {cve_id}")
    nvd_data = get_cve_details(cve_id)
    if not nvd_data:
        print(f"Could not retrieve NVD data for {cve_id}.")
        return None

    # 1. CVSS Score (Baseline)
    cvss_score_v3 = None
    cvss_score_v2 = None
    cvss_version = None

    if nvd_data.get("metrics", {}).get("cvssMetricV31"):
        cvss_score_v3 = nvd_data["metrics"]["cvssMetricV31"][0]["cvssData"].get("baseScore")
        cvss_version = "3.1"
    elif nvd_data.get("metrics", {}).get("cvssMetricV30"):
        cvss_score_v3 = nvd_data["metrics"]["cvssMetricV30"][0]["cvssData"].get("baseScore")
        cvss_version = "3.0"

    if cvss_score_v3 is not None:
        scaled_cvss = (float(cvss_score_v3) / 10.0) * 7.0
        cvss_used = float(cvss_score_v3)
    else: # Fallback to CVSS v2 if v3 not available
        if nvd_data.get("metrics", {}).get("cvssMetricV2"):
            cvss_score_v2_data = nvd_data["metrics"]["cvssMetricV2"][0]
            cvss_score_v2 = cvss_score_v2_data["cvssData"].get("baseScore")
            cvss_version = "2.0"
            if cvss_score_v2 is not None:
                scaled_cvss = (float(cvss_score_v2) / 10.0) * 7.0
                cvss_used = float(cvss_score_v2)
            else:
                scaled_cvss = 0.0 # No CVSS score found
                cvss_used = 0.0
                cvss_version = "N/A"
        else:
            scaled_cvss = 0.0 # No CVSS score found
            cvss_used = 0.0
            cvss_version = "N/A"

    print(f"  CVSS Score ({cvss_version}): {cvss_used if cvss_used is not None else 'N/A'}, Scaled to 7: {scaled_cvss:.2f}")

    # 2. EPSS Score
    epss_score, epss_percentile = get_epss_score(cve_id)
    time.sleep(REQUEST_DELAY_SECONDS_EPSS) # Delay after EPSS call

    epss_contribution = 0.0
    if epss_score is not None:
        epss_contribution = epss_score * 2.0
        print(f"  EPSS Score: {epss_score:.4f} (Percentile: {epss_percentile:.4f}), Contribution: {epss_contribution:.2f}")
    else:
        print(f"  EPSS Score: Not available or error, Contribution: 0.0")

    # 3. KEV Modifier
    kev_modifier = 0.0
    # NVD JSON structure for KEV: cve.cisaExploitAdd (date added to KEV)
    # Other fields: cisaActionDue, cisaRequiredAction, cisaVulnerabilityName
    is_in_kev = bool(nvd_data.get("cisaExploitAdd"))
    if is_in_kev:
        kev_modifier = 1.0
        print(f"  KEV Status: In CISA KEV, Modifier: +{kev_modifier:.2f}")
    else:
        print(f"  KEV Status: Not in CISA KEV, Modifier: +0.0")


    # 4. Patch Availability Modifier
    patch_status = check_patch_availability(nvd_data.get("references", []))
    patch_modifier = 0.0
    if patch_status == PATCH_AVAILABLE:
        patch_modifier = -1.0
    elif patch_status == NO_PATCH_CONFIRMED:
        patch_modifier = 0.5
    # WORKAROUND_AVAILABLE or PATCH_STATUS_UNKNOWN results in 0.0 modifier

    print(f"  Patch Status: {patch_status}, Modifier: {patch_modifier:.2f}")

    # Calculate Final Score
    total_score = scaled_cvss + epss_contribution + kev_modifier + patch_modifier
    final_score = max(0.0, min(10.0, total_score)) # Cap between 0 and 10

    print(f"  Calculated Score Components: CVSS_scaled={scaled_cvss:.2f}, EPSS_contrib={epss_contribution:.2f}, KEV_mod={kev_modifier:.2f}, Patch_mod={patch_modifier:.2f}")
    print(f"  Pre-cap Total Score: {total_score:.2f}")
    print(f"  Final Score (0-10): {final_score:.2f}")

    return {
        "cve_id": cve_id,
        "final_score": round(final_score, 2),
        "cvss_version": cvss_version,
        "cvss_base_score": cvss_used if cvss_used is not None else None,
        "cvss_scaled_contribution": round(scaled_cvss, 2),
        "epss_score": epss_score,
        "epss_percentile": epss_percentile,
        "epss_contribution": round(epss_contribution, 2),
        "in_kev": is_in_kev,
        "kev_modifier": round(kev_modifier, 2),
        "patch_status": patch_status,
        "patch_modifier": round(patch_modifier, 2),
        "interpretation": get_score_interpretation(final_score)
    }

def get_score_interpretation(score: float) -> str:
    """Returns a textual interpretation of the score."""
    if score >= 9.0:
        return "CRITICAL Risk"
    elif score >= 7.0:
        return "HIGH Risk"
    elif score >= 4.0:
        return "MEDIUM Risk"
    elif score > 0: # Changed from 0.1 to handle scores like 0.05 correctly
        return "LOW Risk"
    else: # score == 0.0
        return "VERY LOW / Informational"

if __name__ == "__main__":
    sample_cves_for_scoring = [
        "CVE-2021-44228",  # Log4Shell (should be high/critical)
        "CVE-2019-1010218", # Moderate CVSS, check EPSS/KEV
        "CVE-2017-0144",   # EternalBlue (should be high/critical, likely in KEV)
        "CVE-2020-0796",   # SMBGhost (High CVSS, check KEV/EPSS)
        "CVE-2023-38646",  # Recent Metabase RCE (check how new CVEs are handled by EPSS)
        "CVE-2008-4250",   # MS08-067, old but gold (likely KEV, EPSS might be lower due to age of typical data)
        "CVE-2024-0204"    # A very recent one at time of writing (Jan 2024)
    ]

    all_results = []
    # Add a general delay for NVD fetcher as it's shared
    # The cve_fetcher itself has a delay in its __main__, but not when called as a library.
    # We'll rely on the EPSS delay for now and the NVD one if running the fetcher's main.
    # For library use, direct delays are better.
    # NVD_REQUEST_DELAY = 6 # From cve_fetcher

    for cve in sample_cves_for_scoring:
        result = calculate_risk_score(cve)
        if result:
            all_results.append(result)
            print(f"  Interpretation: {result['interpretation']}")
        else:
            print(f"Could not analyze {cve}.")

        if cve != sample_cves_for_scoring[-1]:
             # Delay before the *next* NVD fetch, EPSS fetch has its own internal delay
             print(f"Waiting {6} seconds before next NVD fetch...")
             time.sleep(6)


    print("\n\n--- Scoring Summary ---")
    for res in all_results:
        print(f"CVE: {res['cve_id']}, Score: {res['final_score']:.2f} ({res['interpretation']})")
        print(f"  CVSS: {res['cvss_base_score']} ({res['cvss_version']}), EPSS: {res['epss_score'] if res['epss_score'] is not None else 'N/A'}, KEV: {res['in_kev']}, Patch: {res['patch_status']}")

    # Test a CVE that might not have NVD data or EPSS data
    print("\n--- Testing a potentially non-existent CVE ---")
    calculate_risk_score("CVE-2099-99999") # Should fail NVD
    time.sleep(6)
    # Find a CVE that exists in NVD but likely not in EPSS (e.g., very old or non-software)
    # For now, the existing invalid test in cve_fetcher covers NVD not found.
    # EPSS not found is handled by get_epss_score returning None.

    print("\n--- Legend for CVE Risk Profile Score (0-10) ---")
    print("9.0 - 10.0: CRITICAL Risk - Highest priority. Likely actively exploited or very high probability, high CVSS, potentially no easy patch.")
    print("7.0 -  8.9: HIGH Risk - Urgent attention. High CVSS and/or significant exploitation indicators.")
    print("4.0 -  6.9: MEDIUM Risk - Consider for remediation. Moderate CVSS, and/or some exploitation indicators or no patch.")
    print("0.1 -  3.9: LOW Risk - Monitor. Lower CVSS, low exploitation probability, and/or patch available.")
    print("0.0 -      : VERY LOW / Informational - Minimal immediate risk based on current data.")
