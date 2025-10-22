Here is the `README.md` file in English.

-----

# Nmap Vulnerability Scanner Script

This Python script automates Nmap vulnerability scans against a list of targets. It reads targets from a file, runs parallelized `nmap` scans using the `--script vuln` argument, extracts CVE information, and enriches it via the NVD API.

## Features

  * **Parallel Scanning:** Uses a `ThreadPoolExecutor` (10 workers by default) to scan multiple hosts concurrently.
  * **Target Import:** Reads target IPs or hostnames from a simple text file (defaults to `targets.txt`).
  * **Comprehensive Scan:** Runs an `nmap` scan with the arguments `-sV -T4 -p- -Pn --script vuln` to check all ports for known vulnerabilities.
  * **CVE Extraction:** Parses the nmap output (both XML and script text) to identify `CVE-IDs`.
  * **NVD Enrichment:** Queries the [NVD API (v2.0)](https://www.google.com/search?q=https://nvd.nist.gov/developers/v2) for each CVE found to retrieve details like CVSS score, severity, and a description.
  * **Caching:** Caches NVD API results in memory to avoid duplicate requests during a single run.
  * **Reporting:** Automatically generates two report files in the `nmap_reports` directory:
    1.  `vuln_summary_[timestamp].txt`: A compact, human-readable summary of hosts with medium or higher severity.
    2.  `full_scan_[timestamp].json`: A complete JSON report with all collected data, including Nmap output snippets and NVD details.

## Requirements

### System

  * **nmap:** The `nmap` application must be installed and available in the system's PATH.
  * **Python:** Python 3.13 or newer.
  * **Connectivity:** Internet access is required for NVD API queries.

### Python Modules

  * **requests:** 
  `python -m pip install requests`
  * **nmap**
  `python -m pip install python-nmap` 

## Required Files

### Target File (targets.txt)

By default, the script looks for a file named `targets.txt` in the same directory.

  * Create a file named `targets.txt`.
  * Add one target (IP address or hostname) per line.
  * Lines starting with `#` and empty lines are ignored.

**Example `targets.txt`:**

```
# This is a comment
192.168.1.1
192.168.1.10
scanme.nmap.org
example.com
```

## Usage

Run the script from the command line.

**Default Usage (with `targets.txt`):**

### Output

The script will print its progress to the console. When finished, you will find the reports in the `nmap_reports/` sub-directory.

-----

### ⚠️ Warnings

1.  **Scan Duration:** This script uses the Nmap option `-p-`, which scans **all 65,535 ports**. Such a scan can take an **extremely long time** per host (potentially many hours).
2.  **Authorization:** You must have **explicit permission** to scan the systems listed in your targets file. Unauthorized scanning is illegal and unethical.
3.  **NVD API Limits:** The script includes a pause (`NVD_API_SLEEP`) between NVD requests to respect rate limits. If a large number of unique CVEs are found, the enrichment phase may still take some time.