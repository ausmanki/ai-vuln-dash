import os
import re
import time
import google.generativeai as genai

# Assuming cve_analyzer and cve_fetcher are in the same directory or accessible via PYTHONPATH
from cve_analyzer import calculate_risk_score, get_epss_score as fetch_epss_data, check_patch_availability, PATCH_STATUS_UNKNOWN, PATCH_AVAILABLE, NO_PATCH_CONFIRMED, WORKAROUND_AVAILABLE
from cve_fetcher import get_cve_details
from cve_fetcher import REQUEST_DELAY_SECONDS as NVD_API_REQUEST_DELAY

# --- Constants ---
CVE_PATTERN_CHAT = re.compile(r"(CVE-(?:1999|2\d{3})-(?:\d{4,}))", re.IGNORECASE)

# Intent definitions
INTENT_GET_EPSS = "get_epss"
INTENT_GET_KEV = "get_kev"
INTENT_GET_PATCH = "get_patch"
INTENT_GET_SUMMARY = "get_summary" # General summary or "tell me about"
INTENT_GET_RISK_SCORE = "get_risk_score"
INTENT_GET_DESCRIPTION = "get_description"
INTENT_GET_REFERENCES = "get_references"
INTENT_UNKNOWN = "unknown"

INTENT_KEYWORDS = {
    INTENT_GET_EPSS: [r"epss", r"exploit prediction"],
    INTENT_GET_KEV: [r"kev", r"known exploit", r"exploited in wild", r"cisa list"],
    INTENT_GET_PATCH: [r"patch", r"fix", r"remediation", r"solution", r"patched"],
    INTENT_GET_SUMMARY: [r"summary", r"summarize", r"tell me about", r"details", r"overview", r"info for"],
    INTENT_GET_RISK_SCORE: [r"score", r"risk", r"severity", r"rating", r"how bad"],
    INTENT_GET_DESCRIPTION: [r"description", r"what is it", r"explain"],
    INTENT_GET_REFERENCES: [r"references", r"links", r"advisories"],
}

# --- Global Variables ---
gemini_model = None
is_gemini_configured = False

# --- Score Legend ---
def print_score_legend():
    """Prints the interpretation legend for the CVE Risk Profile Score."""
    print("\n--- Legend for CVE Risk Profile Score (0-10) ---")
    print("9.0 - 10.0: CRITICAL Risk - Highest priority. Likely actively exploited or very high probability, high CVSS, potentially no easy patch.")
    print("7.0 -  8.9: HIGH Risk - Urgent attention. High CVSS and/or significant exploitation indicators.")
    print("4.0 -  6.9: MEDIUM Risk - Consider for remediation. Moderate CVSS, and/or some exploitation indicators or no patch.")
    print("0.1 -  3.9: LOW Risk - Monitor. Lower CVSS, low exploitation probability, and/or patch available.")
    print("0.0        : VERY LOW / Informational - Minimal immediate risk based on current data.")
    print("--------------------------------------------------")

# --- LLM and Configuration ---
def configure_gemini():
    global gemini_model, is_gemini_configured
    try:
        api_key = os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            print("Warning: GOOGLE_API_KEY environment variable not found. LLM features will be disabled.")
            is_gemini_configured = False
            gemini_model = None
            return False

        genai.configure(api_key=api_key)
        gemini_model = genai.GenerativeModel(model_name='gemini-1.5-flash-latest')
        print("Gemini LLM configured successfully with gemini-1.5-flash-latest.")
        is_gemini_configured = True
        return True
    except Exception as e:
        print(f"Error configuring Gemini LLM: {e}")
        gemini_model = None
        is_gemini_configured = False
        return False

def generate_llm_response(user_query: str, cve_id: str, intent:str, fetched_data: dict) -> str:
    if not is_gemini_configured or not gemini_model:
        return "LLM not available or not configured."

    # Build a targeted prompt
    prompt_context = f"The user asked about {cve_id}: \"{user_query}\"\n"
    prompt_context += f"Their specific interest seems to be: {intent}\n\n"
    prompt_context += "Here's the relevant data I found:\n"

    if intent == INTENT_GET_EPSS and "epss_score" in fetched_data:
        prompt_context += f"- EPSS Score: {fetched_data['epss_score']:.4f} (Percentile: {fetched_data['epss_percentile']:.4f})\n"
    elif intent == INTENT_GET_KEV and "kev_status" in fetched_data:
        prompt_context += f"- CISA KEV Status: {'Exploited (in KEV)' if fetched_data['kev_status'] else 'Not listed in KEV'}\n"
    elif intent == INTENT_GET_PATCH and "patch_status" in fetched_data:
        prompt_context += f"- Patch Status (heuristic): {fetched_data['patch_status']}\n"
        if "references" in fetched_data and fetched_data['patch_status'] != PATCH_STATUS_UNKNOWN:
             prompt_context += "  Key references related to patches/advisories might include:\n"
             for ref in fetched_data["references"][:2]: # Show top 2 relevant for brevity
                 if any(tag in ref.get("tags", []) for tag in ["Patch", "Vendor Advisory"]):
                     prompt_context += f"    - {ref.get('url')}\n"
    elif intent == INTENT_GET_DESCRIPTION and "description" in fetched_data:
        prompt_context += f"- Description: {fetched_data['description']}\n"
    elif intent == INTENT_GET_REFERENCES and "references" in fetched_data:
        prompt_context += "- References:\n"
        for i, ref in enumerate(fetched_data["references"][:3]):
             ref_tags = ", ".join(ref.get("tags", []))
             prompt_context += f"  - {ref.get('url')} (Tags: {ref_tags if ref_tags else 'N/A'})\n"

    # For summary or risk score, include more comprehensive data
    if intent in [INTENT_GET_SUMMARY, INTENT_GET_RISK_SCORE] and "full_analysis" in fetched_data:
        analysis = fetched_data["full_analysis"]
        prompt_context += f"- Calculated Risk Score (0-10): {analysis['final_score']:.2f} ({analysis['interpretation']})\n"
        prompt_context += f"- CVSS Score: {analysis['cvss_base_score']} ({analysis['cvss_version']})\n"
        prompt_context += f"- EPSS Score: {analysis['epss_score'] if analysis['epss_score'] is not None else 'N/A'} (Percentile: {analysis['epss_percentile'] if analysis['epss_percentile'] is not None else 'N/A'})\n"
        prompt_context += f"- In CISA KEV: {analysis['in_kev']}\n"
        prompt_context += f"- Patch Status: {analysis['patch_status']}\n"
        if "description" in fetched_data:
             prompt_context += f"- Description: {fetched_data['description']}\n"

    prompt_context += "\nBased on this information and the user's query, provide a concise, helpful, and conversational answer. "
    prompt_context += "If the data for the specific intent is 'N/A' or not found, state that clearly."

    # print(f"\n--- Gemini Prompt ---\n{prompt_context}\n--- End Gemini Prompt ---")
    try:
        response = gemini_model.generate_content(prompt_context)
        return response.text
    except Exception as e:
        print(f"Error generating response from Gemini: {e}")
        return f"LLM Error: Could not get a response. Details: {str(e)[:100]}"

# --- Intent Parsing ---
def parse_intent(user_query: str) -> str:
    query_lower = user_query.lower()
    for intent, keywords in INTENT_KEYWORDS.items():
        for keyword in keywords:
            if re.search(keyword, query_lower):
                return intent
    # Default to summary if a CVE is mentioned but no specific intent keywords
    if CVE_PATTERN_CHAT.search(query_lower):
        return INTENT_GET_SUMMARY
    return INTENT_UNKNOWN

# --- Main Orchestration ---
def handle_cve_query(user_query: str, cve_id: str):
    intent = parse_intent(user_query)
    print(f"  CVE ID: {cve_id}, Detected Intent: {intent}")

    if intent == INTENT_UNKNOWN and not CVE_PATTERN_CHAT.search(user_query): # No CVE and unknown intent
        if is_gemini_configured:
            print("  No CVE ID and unclear intent. Asking LLM for a general response...")
            response = generate_llm_response(user_query, "N/A", INTENT_UNKNOWN, {"query": user_query})
            print(f"\nLLM: {response}")
        else:
            print("  LLM not configured. Please ask a question about a specific CVE ID or a more general query if LLM was enabled.")
        return

    # Fetch base NVD data once
    print(f"  Fetching NVD data for {cve_id}...")
    nvd_data = get_cve_details(cve_id)
    time.sleep(NVD_API_REQUEST_DELAY / 2) # Half delay after NVD, other half after EPSS if called

    if not nvd_data:
        print(f"  Could not retrieve NVD data for {cve_id}.")
        return

    fetched_data_for_llm = {"cve_id": cve_id}
    if nvd_data.get('descriptions'):
        fetched_data_for_llm["description"] = next((d['value'] for d in nvd_data['descriptions'] if d['lang'] == 'en'), "N/A")
    if nvd_data.get('references'):
        fetched_data_for_llm["references"] = nvd_data.get('references', [])


    # Orchestrate based on intent
    if intent == INTENT_GET_EPSS:
        epss_score, epss_percentile = fetch_epss_data(cve_id)
        time.sleep(NVD_API_REQUEST_DELAY / 2)
        fetched_data_for_llm["epss_score"] = epss_score
        fetched_data_for_llm["epss_percentile"] = epss_percentile
        if epss_score is None:
            print(f"  EPSS score not available for {cve_id}.")

    elif intent == INTENT_GET_KEV:
        fetched_data_for_llm["kev_status"] = bool(nvd_data.get("cisaExploitAdd"))

    elif intent == INTENT_GET_PATCH:
        fetched_data_for_llm["patch_status"] = check_patch_availability(nvd_data.get("references", []))

    elif intent == INTENT_GET_DESCRIPTION:
        # Description already added to fetched_data_for_llm if available
        pass

    elif intent == INTENT_GET_REFERENCES:
        # References already added to fetched_data_for_llm if available
        pass

    # For summary or risk score, we need the full analysis
    if intent in [INTENT_GET_SUMMARY, INTENT_GET_RISK_SCORE]:
        print(f"  Calculating full risk score for {cve_id}...")
        # Note: calculate_risk_score currently calls get_cve_details and get_epss_score internally.
        # For full optimization, it could accept pre-fetched NVD/EPSS data.
        # For this refactor, we accept the redundant calls for module independence.
        full_analysis_results = calculate_risk_score(cve_id) # This has its own delays
        if full_analysis_results:
            fetched_data_for_llm["full_analysis"] = full_analysis_results
            # Display structured score for these intents
            print("\n  --- Structured Analysis ---")
            print(f"  Risk Score: {full_analysis_results['final_score']:.2f} ({full_analysis_results['interpretation']})")
            print(f"    CVSS: {full_analysis_results['cvss_base_score']} ({full_analysis_results['cvss_version']})")
            print(f"    EPSS: {full_analysis_results['epss_score'] if full_analysis_results['epss_score'] is not None else 'N/A'}")
            print(f"    KEV: {full_analysis_results['in_kev']}")
            print(f"    Patch: {full_analysis_results['patch_status']}")
        else:
            print(f"  Could not perform full analysis for {cve_id}.")
            # Fallback or error message for LLM
            fetched_data_for_llm["full_analysis"] = {"error": "Analysis failed"}


    # Generate and print LLM response
    if is_gemini_configured:
        print(f"\n  Asking Gemini (Intent: {intent})...")
        llm_response = generate_llm_response(user_query, cve_id, intent, fetched_data_for_llm)
        print(f"\nLLM: {llm_response}")
    else:
        # If LLM is not configured, provide whatever specific data was fetched for non-summary intents
        if intent == INTENT_GET_EPSS and "epss_score" in fetched_data_for_llm:
             print(f"  EPSS Score for {cve_id}: {fetched_data_for_llm['epss_score'] if fetched_data_for_llm['epss_score'] is not None else 'N/A'}")
        elif intent == INTENT_GET_KEV and "kev_status" in fetched_data_for_llm:
             print(f"  KEV Status for {cve_id}: {'Exploited (in KEV)' if fetched_data_for_llm['kev_status'] else 'Not listed in KEV'}")
        elif intent == INTENT_GET_PATCH and "patch_status" in fetched_data_for_llm:
             print(f"  Patch Status for {cve_id}: {fetched_data_for_llm['patch_status']}")
        elif intent == INTENT_GET_DESCRIPTION and "description" in fetched_data_for_llm:
             print(f"  Description for {cve_id}: {fetched_data_for_llm['description']}")
        elif intent not in [INTENT_GET_SUMMARY, INTENT_GET_RISK_SCORE]: # if not already handled by full analysis print
            print("  LLM is not configured to provide a conversational answer for this specific query.")


# --- Chat Loop ---
def chat():
    print("Welcome to the Smart CVE Assistant!")
    configure_gemini()

    simulated_inputs = [
        # Test 1: Older CVE, potentially less data / only CVSSv2
        "info on CVE-2000-0001",
        # Test 4: Chatbot with ambiguous query (where CVE is present)
        "Tell me something about CVE-2021-44228 and its patches or exploits.",
        "show legend", # Keep this to ensure it still works
        "quit"
    ]
    input_iterator = iter(simulated_inputs)

    while True:
        try:
            user_input = next(input_iterator)
            print(f"\n\n>>> User: {user_input}")
        except StopIteration:
            print("\nEnd of simulated inputs.")
            break

        if user_input.lower() == 'quit':
            print("\nExiting CVE Assistant. Goodbye!")
            break
        if not user_input:
            continue

        if user_input.lower() in ["legend", "show legend", "explain score", "help score"]:
            print_score_legend()
            continue

        cve_match = CVE_PATTERN_CHAT.search(user_input)
        if cve_match:
            cve_id = cve_match.group(1).upper()
            handle_cve_query(user_input, cve_id)
        else: # No CVE ID found in the query
            handle_cve_query(user_input, "N/A") # Pass "N/A" or similar to indicate no specific CVE

        # General delay between processing user inputs fully
        if user_input.lower() != "quit":
            print(f"\n(Main loop: Waiting {NVD_API_REQUEST_DELAY}s before next simulated input for API cooldowns)")
            time.sleep(NVD_API_REQUEST_DELAY)

if __name__ == "__main__":
    chat()
