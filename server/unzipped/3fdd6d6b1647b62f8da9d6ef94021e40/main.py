
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import requests
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
import pandas as pd

app = FastAPI()
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory="static"), name="static")

ARMORCODE_URL = "https://app.armorcode.com/user/findings/"

def load_api_key():
    path = BASE_DIR / "ArmorCode_API_key.txt"
    if not path.exists():
        raise RuntimeError("❌ Missing ArmorCode_API_key.txt")
    return path.read_text().strip()

armor_api_key = load_api_key()

def normalize(value):
    return str(value).strip().lower() if value else ""

def generate_dedup_hash(finding):
    cve = normalize(finding.get("cve"))
    component = normalize(finding.get("componentName"))
    version = normalize(finding.get("componentVersion"))
    title = normalize(finding.get("title"))
    tool = normalize(finding.get("toolName") or finding.get("scanType"))
    file_path = normalize(finding.get("filePath") or finding.get("location") or "")
    env = normalize(finding.get("environmentName"))
    raw = f"{cve}|{component}|{version}|{title}|{tool}|{file_path}|{env}"
    return hashlib.sha256(raw.encode()).hexdigest()

def deduplicate(findings):
    seen = set()
    deduped = []
    for f in findings:
        h = generate_dedup_hash(f)
        f["dedupHash"] = h
        if h not in seen:
            seen.add(h)
            deduped.append(f)
    return deduped

def convert_timestamp(ts):
    try:
        return datetime.fromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M")
    except:
        return None

def group_by_cve_component_version(findings):
    result = defaultdict(lambda: defaultdict(list))
    for f in findings:
        raw_cve = f.get("cve")
        if isinstance(raw_cve, list):
            cve = ", ".join(raw_cve)
        else:
            cve = raw_cve or "No CVE"
        component = f.get("componentName") or "Unknown Component"
        version = f.get("componentVersion") or "Unknown Version"
        key = f"{component}:{version}"
        result[cve][key].append(f)
    return result

def fetch_findings(start_date, end_date):
    headers = {
        "Authorization": f"Bearer {armor_api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "size": 500,
        "page": 0,
        "sortColumns": [{"property": "riskScore", "direction": "desc"}],
        "createdStartDate": start_date,
        "createdEndDate": end_date,
        "ticketStatusRequired": False,
        "ignoreDuplicate": False,
        "filters": {
            "status": ["OPEN", "TRIAGE", "CONFIRMED"]
        },
        "filterOperations": {
            "status": "OR"
        }
    }
    res = requests.post(ARMORCODE_URL, headers=headers, json=payload)
    res.raise_for_status()
    return res.json().get("content", [])

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00.000Z")
    end = datetime.now().strftime("%Y-%m-%dT23:59:59.999Z")
    findings = fetch_findings(start, end)
    deduped = deduplicate(findings)
    grouped = group_by_cve_component_version(deduped)
    summary = {
        "total": len(findings),
        "deduped": len(deduped),
        "unique_cves": len(grouped),
        "top_cves": sorted([(k, sum(len(v) for v in g.values())) for k, g in grouped.items()], key=lambda x: -x[1])[:5]
    }
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "summary": summary,
        "grouped": grouped
    })
