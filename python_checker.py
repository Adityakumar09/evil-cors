import requests
import csv
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# Target Website
BASE_URL = "https://sales-crm.dev.ispinnyworks.in"

# Output CSV File
OUTPUT_FILE = "security_header_report.csv"

# Headers to Check
HEADERS_TO_CHECK = [
    "X-Frame-Options",
    "Content-Security-Policy"
]

# Pages to Scan (Add more if needed, or crawl dynamically)
pages = [
    "/",
    "/loan-app",
    "/login",
    "/clientaccesspolicy.xml",
    "/crossdomain.xml",
    "/build/",
    "/build/assets/",
    "/build/favicons/",
    "/build/images/",
    "/robots.txt"
]

# Function to Check Headers
def check_headers(url):
    result = {
        "URL": url,
        "X-Frame-Options": "Missing",
        "CSP frame-ancestors": "Missing"
    }
    try:
        response = requests.get(url, timeout=10, verify=True)

        # Check for X-Frame-Options
        x_frame_options = response.headers.get("X-Frame-Options", "Missing")
        result["X-Frame-Options"] = x_frame_options

        # Check for CSP and frame-ancestors inside it
        csp = response.headers.get("Content-Security-Policy", "Missing")
        if csp != "Missing":
            if "frame-ancestors" in csp:
                ancestors = [part.strip() for part in csp.split(";") if "frame-ancestors" in part]
                result["CSP frame-ancestors"] = ancestors[0] if ancestors else "Missing"
            else:
                result["CSP frame-ancestors"] = "Missing"
        return result

    except requests.RequestException as e:
        print(f"[!] Error fetching {url}: {e}")
        result["X-Frame-Options"] = "Error"
        result["CSP frame-ancestors"] = "Error"
        return result

# Function to write CSV
def write_csv(data):
    with open(OUTPUT_FILE, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["URL", "X-Frame-Options", "CSP frame-ancestors"])
        writer.writeheader()
        for row in data:
            writer.writerow(row)

# Main Execution
def main():
    results = []
    for page in pages:
        full_url = urljoin(BASE_URL, page)
        print(f"[*] Checking {full_url}")
        results.append(check_headers(full_url))
    
    write_csv(results)
    print(f"[✔️] Report generated: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
