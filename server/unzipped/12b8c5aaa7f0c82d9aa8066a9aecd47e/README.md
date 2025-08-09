# Vulnerability Scanner Agent Documentation

## Overview

The Vulnerability Scanner Agent is a tool built using Google's Agent Development Kit (ADK) that collects vulnerability data from multiple sources including CVE.org, EPSS, and CISA KEV, and provides patch links when available. This agent helps security professionals prioritize vulnerabilities based on severity, exploitation likelihood, and active exploitation status.

## Features

- **CVE Data Collection**: Retrieves vulnerability information from the National Vulnerability Database (NVD)
- **EPSS Score Collection**: Gets exploit prediction scores to determine likelihood of exploitation
- **CISA KEV Integration**: Checks if vulnerabilities are in the Known Exploited Vulnerabilities catalog
- **Patch Link Finding**: Searches for remediation information and patch links
- **Risk Prioritization**: Automatically prioritizes vulnerabilities based on multiple risk factors
- **Interactive Interface**: Allows users to query for vulnerability information using natural language

## Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager
- Virtual environment (recommended)

### Setup

1. Clone the repository or download the source code
2. Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required dependencies:

```bash
pip install google-adk beautifulsoup4 requests
```

## Project Structure

```
vulnerability-scanner-agent/
├── cve_data_collector.py       # CVE data collection component
├── epss_score_collector.py     # EPSS score collection component
├── cisa_kev_collector.py       # CISA KEV data collection component
├── patch_link_finder.py        # Patch link finder component
├── vulnerability_scanner_agent.py  # Main integration module
├── test_vulnerability_scanner.py   # Test script
└── README.md                   # Documentation
```

## Component Details

### CVE Data Collector

The CVE Data Collector interfaces with the NVD API to retrieve vulnerability information. It supports:

- Searching by CVE ID
- Searching by keywords
- Filtering by date ranges
- Filtering by CVSS severity

Example usage:

```python
from cve_data_collector import CVEDataCollector

collector = CVEDataCollector()
result = collector.search_cve(cve_id="CVE-2021-44228")
```

### EPSS Score Collector

The EPSS Score Collector retrieves exploit prediction scores from the EPSS API. These scores indicate the likelihood that a vulnerability will be exploited in the wild.

Example usage:

```python
from epss_score_collector import EPSSScoreCollector

collector = EPSSScoreCollector()
result = collector.get_score("CVE-2021-44228")
```

### CISA KEV Collector

The CISA KEV Collector checks if vulnerabilities are in the CISA Known Exploited Vulnerabilities catalog, which contains vulnerabilities that are being actively exploited.

Example usage:

```python
from cisa_kev_collector import CISAKEVCollector

collector = CISAKEVCollector()
result = collector.check_vulnerability("CVE-2021-44228")
```

### Patch Link Finder

The Patch Link Finder searches for patch information and remediation links from various sources including vendor advisories and GitHub.

Example usage:

```python
from patch_link_finder import PatchLinkFinder

finder = PatchLinkFinder()
result = finder.find_patch_links("CVE-2021-44228")
```

## Using the Agent

### Running the Agent

To run the agent in interactive mode:

```python
from vulnerability_scanner_agent import run_agent_interactive

run_agent_interactive()
```

### Example Queries

The agent can handle various types of queries, such as:

- "Tell me about CVE-2021-44228"
- "Find vulnerabilities related to log4j"
- "Is CVE-2021-44228 being actively exploited?"
- "Where can I find patches for CVE-2021-44228?"
- "What vulnerabilities were recently added to CISA KEV?"

### Risk Scoring

The agent prioritizes vulnerabilities based on the following factors:

1. Presence in CISA KEV catalog (highest priority - actively exploited)
2. EPSS score (higher scores indicate greater likelihood of exploitation)
3. CVSS score (standard severity rating)
4. Availability of patches (vulnerabilities without patches are higher priority)

## API Reference

### CVEDataCollector

```python
def search_cve(cve_id=None, keywords=None, published_start_date=None, published_end_date=None, last_modified_start_date=None, last_modified_end_date=None, cvss_v3_severity=None, max_results=20)
```

### EPSSScoreCollector

```python
def get_score(cve_id)
def get_scores_batch(cve_ids)
def download_bulk_data()
```

### CISAKEVCollector

```python
def check_vulnerability(cve_id)
def check_vulnerabilities_batch(cve_ids)
def get_recent_additions(days=30)
```

### PatchLinkFinder

```python
def find_patch_links(cve_id, vendor=None)
def find_patch_links_batch(cve_ids, vendor=None)
```

## Testing

The project includes a comprehensive test suite that validates all components:

```bash
python test_vulnerability_scanner.py
```

## Limitations and Considerations

- **API Rate Limiting**: The NVD API has rate limits (5 requests per 30 seconds for unauthenticated users)
- **Data Freshness**: EPSS scores and CISA KEV data are updated periodically by their respective sources
- **Patch Link Accuracy**: The patch link finder uses heuristics and may not find all available patches

## Future Enhancements

- Add support for more vulnerability data sources
- Implement caching to reduce API calls
- Add a web interface for easier interaction
- Integrate with security tools and platforms
- Add support for vulnerability trend analysis

## Troubleshooting

### Common Issues

1. **API Connection Errors**: Ensure you have internet connectivity and the APIs are available
2. **Rate Limiting**: If you encounter rate limiting, consider adding delays between requests
3. **Missing Dependencies**: Ensure all required packages are installed

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- National Vulnerability Database (NVD) for CVE data
- FIRST.org for the EPSS scoring system
- CISA for the Known Exploited Vulnerabilities catalog
- Google for the Agent Development Kit (ADK)
