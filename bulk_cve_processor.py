import os
import time
from file_parser import parse_file
from cve_analyzer import calculate_risk_score # NVD_REQUEST_DELAY is in cve_fetcher, not analyzer
from cve_fetcher import REQUEST_DELAY_SECONDS as NVD_REQUEST_DELAY # Using the one from cve_fetcher

def process_cve_file(file_path: str):
    """
    Parses a file to extract CVE IDs, then analyzes each CVE.

    Args:
        file_path: Path to the file (CSV, XLS, XLSX, PDF) containing CVE IDs.
    """
    print(f"Starting bulk processing for file: {file_path}")

    # Check if file exists before attempting to parse
    if not os.path.exists(file_path):
        print(f"Error: File not found at {file_path}")
        return

    extracted_cves = parse_file(file_path)

    if extracted_cves is None:
        print(f"Could not parse the file or file type is unsupported: {file_path}")
        return

    if not extracted_cves:
        print(f"No CVEs found in {file_path}.")
        return

    print(f"Found {len(extracted_cves)} unique CVE(s) in {file_path}: {sorted(list(extracted_cves))}")

    all_analysis_results = []

    for i, cve_id in enumerate(sorted(list(extracted_cves))): # Process in sorted order for consistent output
        print(f"\n--- Analyzing CVE {i+1}/{len(extracted_cves)}: {cve_id} ---")
        analysis_result = calculate_risk_score(cve_id)
        if analysis_result:
            all_analysis_results.append(analysis_result)
            print(f"  Score for {cve_id}: {analysis_result['final_score']} ({analysis_result['interpretation']})")
        else:
            print(f"  Failed to analyze {cve_id}.")

        # Respect rate limits, especially for NVD. EPSS also has its own internal delay in cve_analyzer.
        # This delay is primarily for the NVD call made by calculate_risk_score.
        if i < len(extracted_cves) - 1: # Don't wait after the last CVE
            print(f"Waiting for {NVD_REQUEST_DELAY} seconds before next NVD API call...")
            time.sleep(NVD_REQUEST_DELAY)

    print("\n\n--- Bulk Analysis Summary ---")
    if all_analysis_results:
        for result in all_analysis_results:
            print(f"CVE: {result['cve_id']}, Score: {result['final_score']:.2f} ({result['interpretation']}), "
                  f"CVSS: {result['cvss_base_score']}({result['cvss_version']}), EPSS: {result['epss_score'] if result['epss_score'] is not None else 'N/A'}, "
                  f"KEV: {result['in_kev']}, Patch: {result['patch_status']}")
    else:
        print("No CVEs were successfully analyzed.")

    print("\n--- Legend for CVE Risk Profile Score (0-10) ---")
    print("9.0 - 10.0: CRITICAL Risk - Highest priority. Likely actively exploited or very high probability, high CVSS, potentially no easy patch.")
    print("7.0 -  8.9: HIGH Risk - Urgent attention. High CVSS and/or significant exploitation indicators.")
    print("4.0 -  6.9: MEDIUM Risk - Consider for remediation. Moderate CVSS, and/or some exploitation indicators or no patch.")
    print("0.1 -  3.9: LOW Risk - Monitor. Lower CVSS, low exploitation probability, and/or patch available.")
    print("0.0        : VERY LOW / Informational - Minimal immediate risk based on current data.")
    print("--------------------------------------------------")

def main():
    # Ensure dummy files exist by running file_parser.py once if not already run
    # For simplicity, we assume they might exist from a previous run or testing.
    # A more robust test setup would guarantee file creation here.

    TEST_DIR = "test_bulk_files"
    if not os.path.exists(TEST_DIR):
        print(f"Test directory {TEST_DIR} not found. Please ensure dummy files are present for testing.")
        return # Exit main() if test directory is not found

    test_files_to_process = [
        os.path.join(TEST_DIR, "small_test_cves.csv"), # Original test
        os.path.join(TEST_DIR, "empty.csv"),
        os.path.join(TEST_DIR, "no_cves.csv"),
        os.path.join(TEST_DIR, "empty.xlsx"),
        os.path.join(TEST_DIR, "no_cves.xlsx"),
        os.path.join(TEST_DIR, "empty.pdf"),
        os.path.join(TEST_DIR, "no_cves.pdf"),
        os.path.join(TEST_DIR, "non_existent_file.xyz") # Test non-existent file
    ]

    # Ensure small_test_cves.csv exists for the first test case from previous runs
    small_test_csv_content = """CVE-ID,Description
CVE-2021-44228,Log4Shell
cve-2019-0708,BlueKeep
CVE-2023-INVALIDFORMAT,TestInvalid
"""
    if not os.path.exists(os.path.join(TEST_DIR, "small_test_cves.csv")):
        with open(os.path.join(TEST_DIR, "small_test_cves.csv"), "w") as f:
            f.write(small_test_csv_content)
            print(f"Created {os.path.join(TEST_DIR, 'small_test_cves.csv')} for testing.")


    for file_path in test_files_to_process:
        print(f"\n\n----------------------------------------------------")
        print(f"--- Processing Test File: {file_path} ---")
        print(f"----------------------------------------------------")
        process_cve_file(file_path)
        # Add a small delay between processing entire files if needed, though
        # process_cve_file already has per-CVE delays.
        # time.sleep(1)

if __name__ == "__main__":
    main()
