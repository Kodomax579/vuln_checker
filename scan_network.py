"""
nmap_vuln_full_file.py

- Reads target IPs/hosts from a text file (one per line). File path can be provided via --targets-file,
  otherwise defaults to './targets.txt'.
- Uses nmap as a subprocess to capture raw XML (-oX -)
- Always uses: -sV -T4 -p- -Pn --script vuln
- Parallel scans with ThreadPoolExecutor (10 workers)
- Extracts CVE IDs from script outputs (host + port level) and from raw XML
- Enriches CVEs via NVD API (simple per-CVE lookup, cached)
- Writes a compact summary TXT and a full JSON with raw data
- Console output is English-only

Requirements:
  - nmap binary installed & on PATH
  - python modules: requests
  - optionally run as root for best NSE results (sudo)
"""

import subprocess
import json
import os
import re
import requests
import time
import sys
import concurrent.futures
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
import argparse

# -----------------------------
# Configuration (fixed per request)
# -----------------------------
NSE_ARGUMENTS = "-sV -T4 -p- -Pn --script vuln"
OUTPUT_DIR = "nmap_reports"
PERMISSION_CONFIRMED = True
MAX_WORKERS = 10

# NVD enrichment config
CVE_DETAILS_CACHE = {}
SEVERITY_MAPPING = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'NONE': 0}
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", flags=re.IGNORECASE)

# Timeouts and sleeps
NMAP_SUBPROCESS_TIMEOUT = 900  # seconds per host (adjust if needed)
NVD_API_SLEEP = 1.0  # seconds pause between NVD requests to be polite

# -----------------------------
# Helpers
# -----------------------------
def ensure_output_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def load_targets_from_file(path):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Targets file not found: {path}")
    with p.open("r", encoding="utf-8") as fh:
        lines = [line.strip() for line in fh if line.strip() and not line.strip().startswith("#")]
    # deduplicate and keep order
    seen = set()
    unique = []
    for t in lines:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique

def find_cves_from_string(text):
    if not text:
        return []
    found = set(m.group(0).upper() for m in CVE_REGEX.finditer(text))
    return sorted(found)

def get_cve_details(cve_id):
    """Fetch CVE details from NVD (v2.0) and cache results. Returns dict."""
    if cve_id in CVE_DETAILS_CACHE:
        return CVE_DETAILS_CACHE[cve_id]

    print(f"    > NVD lookup for {cve_id} ...")
    try:
        time.sleep(NVD_API_SLEEP)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()

        vuln_entry = None
        try:
            vuln_entry = data.get("vulnerabilities", [])[0].get("cve", {})
        except Exception:
            vuln_entry = None

        if not vuln_entry:
            result = {"id": cve_id, "error": "No NVD entry found"}
            CVE_DETAILS_CACHE[cve_id] = result
            return result

        # description
        description = "No description found."
        for desc in vuln_entry.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", description)
                break

        # determine CVSS score & severity (prefer v3.1)
        score = None
        severity = "NONE"
        metrics = vuln_entry.get("metrics", {})
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            metric = metrics["cvssMetricV31"][0].get("cvssData", {})
            score = metric.get("baseScore")
            severity = metrics["cvssMetricV31"][0].get("baseSeverity", severity)
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            metric = metrics["cvssMetricV30"][0].get("cvssData", {})
            score = metric.get("baseScore")
            severity = metrics["cvssMetricV30"][0].get("baseSeverity", severity)
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            metric = metrics["cvssMetricV2"][0].get("cvssData", {})
            score = metric.get("baseScore")
            severity = metrics["cvssMetricV2"][0].get("baseSeverity", severity)

        result = {
            "id": cve_id,
            "score": score,
            "severity": severity,
            "description": description,
            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        }
        CVE_DETAILS_CACHE[cve_id] = result
        return result

    except requests.RequestException as e:
        err = {"id": cve_id, "error": f"NVD request error: {e}"}
        CVE_DETAILS_CACHE[cve_id] = err
        return err
    except Exception as e:
        err = {"id": cve_id, "error": f"Unknown NVD parsing error: {e}"}
        CVE_DETAILS_CACHE[cve_id] = err
        return err

# -----------------------------
# Nmap subprocess + XML parsing
# -----------------------------
def run_nmap_raw_xml(host, nmap_args):
    """Run nmap as a subprocess and return XML stdout (string). Raises on hard failure."""
    cmd = ["nmap"] + nmap_args.split() + ["-oX", "-", host]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=NMAP_SUBPROCESS_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"nmap timed out for {host}: {e}")
    except FileNotFoundError:
        raise RuntimeError("nmap binary not found. Please install nmap and ensure it's on PATH.")
    except Exception as e:
        raise RuntimeError(f"nmap subprocess failed: {e}")

    if proc.returncode == 2:
        raise RuntimeError(f"nmap returned error code 2 for {host}. stderr: {proc.stderr.strip()}")

    return proc.stdout

def extract_script_texts_from_nmap_xml(xml_text):
    """
    Parse nmap XML and gather all <script> outputs (hostscript + port-level script outputs).
    Returns a concatenated string of outputs.
    """
    if not xml_text:
        return ""
    texts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return xml_text

    for host in root.findall(".//host"):
        for hs in host.findall(".//hostscript/script"):
            out = hs.get("output")
            if out:
                texts.append(out)
        for script in host.findall(".//port/script"):
            out = script.get("output")
            if out:
                texts.append(out)
    return "\n".join(texts)

# -----------------------------
# Core scanning function
# -----------------------------
def scan_single_host(host):
    """
    Run nmap subprocess for host, parse XML script outputs + raw XML for CVEs,
    look up CVE details in NVD, and build a result dict.
    """
    print(f"[{host}] Starting scan ...")
    try:
        xml = run_nmap_raw_xml(host, NSE_ARGUMENTS)
    except Exception as e:
        err = {"error": f"nmap error: {e}", "host_severity": "NONE"}
        print(f"[{host}] ERROR: {e}")
        return host, err

    script_text = extract_script_texts_from_nmap_xml(xml)
    combined_search_text = (script_text or "") + "\n" + (xml or "")

    cve_ids = find_cves_from_string(combined_search_text)
    vulnerabilities = []
    highest_sev_lvl = 0
    host_sev_str = "NONE"

    if cve_ids:
        print(f"[{host}] Found {len(cve_ids)} CVE(s) — fetching details...")
        for c in cve_ids:
            details = get_cve_details(c)
            vulnerabilities.append(details)
            sev = details.get("severity", "NONE")
            lvl = SEVERITY_MAPPING.get(sev.upper(), 0)
            if lvl > highest_sev_lvl:
                highest_sev_lvl = lvl
                host_sev_str = sev

    host_result = {
        "nmap_args": NSE_ARGUMENTS,
        "script_text_sample": (script_text[:2000] + "...") if script_text and len(script_text) > 2000 else script_text,
        "nmap_xml_present": bool(xml),
        "cves_found": cve_ids,
        "vulnerabilities": vulnerabilities,
        "host_severity": host_sev_str
    }

    print(f"[{host}] Scan finished. Highest severity: {host_sev_str}")
    return host, host_result

# -----------------------------
# Report generation
# -----------------------------
def generate_summary_report(all_results):
    """Create a short English TXT summary listing hosts sorted by severity (CRITICAL->LOW)."""
    print("Generating summary report ...")
    hosts_sorted = sorted(all_results.keys(),
                          key=lambda h: SEVERITY_MAPPING.get(all_results[h].get('host_severity', 'NONE'), 0),
                          reverse=True)

    lines = []
    lines.append("=" * 80)
    lines.append("VULNERABILITY SUMMARY REPORT".center(80))
    lines.append("=" * 80)
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z\n")

    for host in hosts_sorted:
        data = all_results.get(host, {})
        severity = data.get('host_severity', 'NONE')
        if severity not in ('CRITICAL', 'HIGH', 'MEDIUM'):
            continue

        lines.append("-" * 80)
        lines.append(f"HOST: {host}    HIGHEST SEVERITY: {severity}")
        lines.append("-" * 80)

        vulns = data.get('vulnerabilities', [])
        if not vulns:
            lines.append("  No CVE details available.")
        else:
            for v in vulns:
                if 'error' in v:
                    lines.append(f"  ▶ {v.get('id')}  ERROR: {v.get('error')}")
                    continue
                lines.append(f"  ▶ {v.get('id')}  Severity: {v.get('severity')}  CVSS: {v.get('score')}")
                desc = v.get('description', '')
                if desc:
                    short_desc = desc if len(desc) <= 300 else desc[:297] + "..."
                    lines.append(f"     Description: {short_desc}")
                lines.append(f"     Link: {v.get('link')}")
                lines.append("     Suggested action: Update affected software to vendor-provided patched versions or follow vendor mitigation guidance.")
                lines.append("")

    if not any("HOST:" in line for line in lines):
        lines.append("No hosts with CRITICAL/HIGH/MEDIUM severity were found.")

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    summary_fname = os.path.join(OUTPUT_DIR, f"vuln_summary_{timestamp}.txt")
    with open(summary_fname, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Saved summary: {summary_fname}")

    json_fname = os.path.join(OUTPUT_DIR, f"full_scan_{timestamp}.json")
    with open(json_fname, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"Saved full JSON data: {json_fname}")

# -----------------------------
# Main
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Nmap vulnerability scanner (reads targets from file).")
    parser.add_argument("--targets-file", "-f", default="targets.txt",
                        help="Path to text file with targets (one per line). Default: ./targets.txt")
    args = parser.parse_args()

    if not PERMISSION_CONFIRMED:
        sys.exit("Permission not confirmed. Exiting.")

    try:
        targets = load_targets_from_file(args.targets_file)
    except Exception as e:
        sys.exit(f"Error loading targets file: {e}")

    if not targets:
        sys.exit("No targets loaded from file. Exiting.")

    ensure_output_dir(OUTPUT_DIR)
    all_results = {}

    print(f"Starting parallel scans for {len(targets)} hosts with {MAX_WORKERS} workers.")
    start = datetime.utcnow()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        futures = {exe.submit(scan_single_host, host): host for host in targets}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                h, result = future.result()
            except Exception as e:
                print(f"[{host}] Unexpected worker error: {e}")
                result = {"error": f"worker exception: {e}", "host_severity": "NONE"}
                h = host
            all_results[h] = result

    elapsed = datetime.utcnow() - start
    print(f"All scans completed in {elapsed} (hh:mm:ss).")

    if all_results:
        generate_summary_report(all_results)
    else:
        print("No results to report.")

if __name__ == "__main__":
    main()
