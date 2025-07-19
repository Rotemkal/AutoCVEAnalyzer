import requests, os
from dotenv import load_dotenv

# Load environment variables from .env file (like the NVD API key)
load_dotenv()

def fetch_cve_details(cve_id):
    try:
        # Prepare headers if the API key is available
        headers = {"apiKey": os.getenv("NVD_API_KEY")} if os.getenv("NVD_API_KEY") else {}

        # Send request to NVD CVE API with a 10-second timeout
        response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",headers=headers, timeout=10)

        # Request failed
        if response.status_code != 200:
            print(f" NVD API error: {response.status_code}")
            return None
        
        # Parse the first vulnerability object from the API response and extract "cve" dictionary containing the main CVE data
        vuln = response.json().get("vulnerabilities", [])[0]
        cve = vuln.get("cve", {})

        # Extract description, next returns only the first that feets
        description = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "Unknown")

        # Extract vendor from CPE
        vendor = extract_vendor(cve)

        # Extract CVSS score and attack vector
        cvss_score, attack_vector = extract_cvss_score_and_vector(vuln)
        
        # Extract published date, remove time part if present
        published_date = cve.get("published", "Unknown")
        if published_date != "Unknown":
            published_date = published_date.split("T")[0]

        # Return all fields in a structured dictionary
        return {'description': description, 'vendor': vendor, 'cvss_score': cvss_score, 'attack_vector': attack_vector, 'published_date': published_date}

    except Exception as e:
        print(f"❌ Error fetching CVE: {e}")
        return None

def extract_vendor(cve):
    """Extract vendor from CPE configurations"""
    try:
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if cpe:
                        parts = cpe.split(":")
                        # parts[3] is the vendor field in CPE format
                        # Extract only valid vendor names
                        if len(parts) >= 4 and parts[3] != "*":
                            vendor = parts[3].replace("_", " ").title()
                            print(f"✅ Vendor: {vendor}")
                            return vendor
        print("❌ Vendor: Unknown")
        return "Unknown"
    except Exception:
        return "Unknown"

def extract_cvss_score_and_vector(vuln):
    """Extract CVSS score and attack vector from metrics"""
    cvss_score, attack_vector = None, "Unknown"
    
    # Find metrics location
    metrics_sources = [
        vuln.get("metrics", {}),
        vuln.get("cve", {}).get("metrics", {}),
        vuln  # Metrics are at top level
    ]
    
    # Find the first source that contains CVSS-related data
    metrics = {}
    for source in metrics_sources:
        if source and any(key.startswith("cvss") for key in source.keys()):
            # Take the whole dict
            metrics = source
            break
    
    # Try CVSS versions in order: v4.0, v3.1, v3.0, v2
    cvss_versions = [("cvssMetricV40", "v4.0"),("cvssMetricV31", "v3.1"), ("cvssMetricV30", "v3.0"), ("cvssMetricV2", "v2.0")]
    
    for metric_key, version in cvss_versions:
        if metric_key in metrics and metrics[metric_key]:
            for metric in metrics[metric_key]:
                cvss_data = metric.get("cvssData", {})
                score = cvss_data.get("baseScore")
                
                if score is not None:
                    cvss_score = score
                    
                    # Get attack vector based on version
                    if version.startswith("v4"):
                        # CVSS v4.0 uses same attack vector as v3.x
                        attack_vector = cvss_data.get("attackVector", "Unknown")
                    elif version.startswith("v3"):
                        attack_vector = cvss_data.get("attackVector", "Unknown")
                    else:
                        # Version is v2
                        # Normalize the access vector for CVSS v2
                        access_vector = cvss_data.get("accessVector", "Unknown")
                        attack_vector = {"NETWORK": "NETWORK", "ADJACENT_NETWORK": "ADJACENT", "LOCAL": "LOCAL"}.get(access_vector, "Unknown")
                    
                    print(f"✅ CVSS {version}: {cvss_score}")
                    return cvss_score, attack_vector
    
    print("❌ CVSS: Not found")
    return cvss_score, attack_vector