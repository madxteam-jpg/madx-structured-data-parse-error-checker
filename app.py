import time
import random
from curl_cffi import requests  # Drop standard requests, use curl_cffi

def inspect_page_structured_data(target_url):
    report = { ... }

    # Rotate realistic headers
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1"
    }

    try:
        # impersonate browser TLS profile (Chrome 124)
        response = requests.get(target_url, headers=headers, impersonate="chrome124", timeout=15)
        report["status_code"] = response.status_code
        
        # ... rest of your BeautifulSoup logic ...
        
    except Exception as err:
        # Handle exceptions
        pass

    return report

# Inside run_batch_audit:
for idx, target_url in enumerate(urls):
    # ... process audit ...
    report = inspect_page_structured_data(target_url)
    results.append(report)
    
    # Introduce random delay between requests to avoid rate limits
    time.sleep(random.uniform(1.5, 4.0))
