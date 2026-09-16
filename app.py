import io
import json
import random
import time
from datetime import datetime
import pandas as pd
import bs4
from bs4 import BeautifulSoup
import streamlit as st
from curl_cffi import requests

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt


def get_stealth_request_config():
    """
    Generates realistic browser headers matching curl_cffi target impersonation.
    """
    browser_profiles = [
        {
            "target": "chrome",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"'
        },
        {
            "target": "chrome",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Chromium";v="123", "Google Chrome";v="123", "Not-A.Brand";v="99"'
        },
        {
            "target": "safari",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
            "sec_ch_ua": None
        }
    ]

    profile = random.choice(browser_profiles)

    headers = {
        "User-Agent": profile["user_agent"],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1"
    }

    if profile["sec_ch_ua"]:
        headers["Sec-Ch-Ua"] = profile["sec_ch_ua"]
        headers["Sec-Ch-Ua-Mobile"] = "?0"
        headers["Sec-Ch-Ua-Platform"] = '"Windows"'

    return profile["target"], headers


def locate_json_error(raw_str, error):
    """Pinpoints line number, column, and snippet where JSON parsing failed."""
    lines = raw_str.splitlines()
    line_no = error.lineno
    col_no = error.colno
    
    start_line = max(0, line_no - 3)
    end_line = min(len(lines), line_no + 2)
    
    snippet_lines = []
    for idx in range(start_line, end_line):
        prefix = " > " if idx == line_no - 1 else "   "
        snippet_lines.append(f"{prefix}Line {idx + 1}: {lines[idx]}")
        if idx == line_no - 1:
            snippet_lines.append("   " + " " * (len(f"Line {idx + 1}: ") + col_no - 1) + "^")
            
    return "\n".join(snippet_lines)


def generate_proof_image(results):
    """Generates a styled PNG image summary card as downloadable proof."""
    total = len(results)
    syntax_errors = sum(1 for r in results if r["syntax_errors"])
    clean_pages = total - syntax_errors
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    fig, ax = plt.subplots(figsize=(10, max(4, len(results) * 0.5 + 2.5)), dpi=150)
    ax.axis('off')

    fig.text(0.05, 0.93, "JSON-LD Syntax Audit Proof", fontsize=18, fontweight='bold', color='#0F172A')
    fig.text(0.05, 0.88, f"Verified On: {timestamp}", fontsize=9, color='#64748B')

    banner_text = f"Total Pages: {total}  |  Syntax Errors: {syntax_errors}  |  Valid Pages: {clean_pages}"
    fig.text(0.05, 0.81, banner_text, fontsize=11, fontweight='bold', color='#1E293B',
             bbox=dict(boxstyle="round,pad=0.5", facecolor="#F1F5F9", edgecolor="#CBD5E1"))

    table_data = [["Target URL", "HTTP", "Scripts", "Syntax Errors", "Status"]]
    for r in results:
        display_url = r["url"] if len(r["url"]) < 45 else r["url"][:42] + "..."
        status_label = "Syntax Error" if r["syntax_errors"] else "Valid Syntax"
        table_data.append([
            display_url,
            str(r["status_code"]),
            str(r["total_scripts"]),
            str(len(r["syntax_errors"])),
            status_label
        ])

    table = ax.table(cellText=table_data, loc='center', cellLoc='left', colWidths=[0.48, 0.12, 0.12, 0.13, 0.15])
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.8)

    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_facecolor('#0F172A')
            cell.set_text_props(color='white', fontweight='bold')
        else:
            if col == 4:
                status_val = table_data[row][4]
                if status_val == "Syntax Error":
                    cell.set_facecolor('#FEE2E2')
                    cell.set_text_props(color='#991B1B', fontweight='bold')
                else:
                    cell.set_facecolor('#DCFCE7')
                    cell.set_text_props(color='#166534', fontweight='bold')
            else:
                cell.set_facecolor('#FFFFFF' if row % 2 == 0 else '#F8FAFC')

    plt.tight_layout()

    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', bbox_inches='tight', dpi=150)
    plt.close(fig)
    img_buffer.seek(0)
    return img_buffer


def inspect_page_structured_data(target_url):
    """Fetches HTML via curl_cffi with TLS/HTTP2 spoofing, extracts JSON-LD, and validates syntax."""
    report = {
        "url": target_url,
        "status_code": "Unknown",
        "total_scripts": 0,
        "has_errors": False,
        "syntax_errors": [],
        "valid_blocks": []
    }

    target_browser, headers = get_stealth_request_config()

    try:
        # Fetching with browser TLS fingerprint spoofing via curl_cffi
        response = requests.get(
            target_url, 
            headers=headers, 
            impersonate=target_browser, 
            timeout=20,
            allow_redirects=True
        )
        report["status_code"] = response.status_code

        # Detect HTTP Error Code blocks (e.g. 403, 429)
        if response.status_code != 200:
            report["has_errors"] = True
            report["syntax_errors"].append({
                "block_index": 0,
                "error_message": f"HTTP Response Status {response.status_code} (Possible anti-bot block/challenge)",
                "snippet": ""
            })
            return report

        # Parse HTML using BeautifulSoup
        soup = BeautifulSoup(response.text, "html.parser")
        script_tags = soup.find_all("script", type="application/ld+json")

        report["total_scripts"] = len(script_tags)

        if len(script_tags) == 0:
            report["has_errors"] = True
            report["syntax_errors"].append({
                "block_index": 0,
                "error_message": "No <script type='application/ld+json'> tags found on this page.",
                "snippet": ""
            })

        for idx, tag in enumerate(script_tags, start=1):
            raw_json = tag.string.strip() if tag.string else ""
            
            # Handle empty tag case or string child mismatch
            if not raw_json and isinstance(tag.contents, list) and len(tag.contents) > 0:
                raw_json = "".join([str(c) for c in tag.contents]).strip()

            block_idx = idx

            if not raw_json:
                report["syntax_errors"].append({
                    "block_index": block_idx,
                    "error_message": "Empty JSON-LD script tag found.",
                    "snippet": ""
                })
                report["has_errors"] = True
                continue

            try:
                parsed_data = json.loads(raw_json)
                
                schema_type = "Unknown"
                if isinstance(parsed_data, dict):
                    schema_type = parsed_data.get("@type", "Object/@graph")
                elif isinstance(parsed_data, list):
                    schema_type = f"Array[{len(parsed_data)} items]"

                report["valid_blocks"].append({
                    "block_index": block_idx,
                    "type": schema_type,
                    "data": parsed_data
                })

            except json.JSONDecodeError as err:
                report["has_errors"] = True
                snippet = locate_json_error(raw_json, err)
                report["syntax_errors"].append({
                    "block_index": block_idx,
                    "error_message": f"{err.msg} (Line {err.lineno}, Col {err.colno})",
                    "snippet": snippet,
                    "raw": raw_json[:300] + "..." if len(raw_json) > 300 else raw_json
                })

    except Exception as err:
        report["status_code"] = f"Error: {type(err).__name__}"
        report["has_errors"] = True
        report["syntax_errors"].append({
            "block_index": 0,
            "error_message": f"Failed to fetch page: {str(err)}",
            "snippet": ""
        })

    return report


def run_batch_audit(urls):
    """Audits input URLs sequentially with randomized delays."""
    results = []
    progress_bar = st.progress(0)
    status_text = st.empty()
    total = len(urls)

    for idx, target_url in enumerate(urls):
        status_text.text(f"Auditing JSON Syntax ({idx + 1}/{total}): {target_url}")
        progress_bar.progress((idx + 1) / total)
        
        report = inspect_page_structured_data(target_url)
        results.append(report)

        # Apply random delay between 1.5 - 3.5s (Skip delay on final request)
        if idx < total - 1:
            time.sleep(random.uniform(1.5, 3.5))

    status_text.empty()
    progress_bar.empty()
    return results


# --- Streamlit UI Layout ---
st.set_page_config(page_title="JSON-LD Syntax Error Checker", layout="wide")
st.title("🏷️ Anti-Bot Resilient JSON-LD Syntax Checker")
st.caption("Parses page source HTML with spoofed browser TLS profiles (`curl_cffi`) to bypass bot filters and audit structured data.")

user_urls_input = st.text_area(
    "Paste URLs to Audit (One per line):",
    height=160,
    placeholder="https://example.com/product-1\nhttps://example.com/blog/article-1"
)

if st.button("Audit JSON Syntax", type="primary"):
    urls = [u.strip() for u in user_urls_input.splitlines() if u.strip()]

    if not urls:
        st.error("Please enter at least one URL to check.")
    else:
        with st.spinner("Bypassing detection & extracting JSON-LD syntax..."):
            try:
                results = run_batch_audit(urls)

                total_pages = len(results)
                pages_with_syntax_err = sum(1 for r in results if r["syntax_errors"])
                clean_pages = total_pages - pages_with_syntax_err

                c1, c2, c3 = st.columns(3)
                c1.metric("Pages Audited", total_pages)
                c2.metric("Syntax Errors Found", pages_with_syntax_err)
                c3.metric("Valid Syntax Pages", clean_pages)

                st.markdown("---")
                st.subheader("Summary Table")

                df_summary = pd.DataFrame([
                    {
                        "URL": r["url"],
                        "HTTP Status": r["status_code"],
                        "JSON-LD Blocks": r["total_scripts"],
                        "Syntax Errors": len(r["syntax_errors"]),
                        "Status": "🔴 Syntax Error" if r["syntax_errors"] else "🟢 Valid Syntax"
                    }
                    for r in results
                ])
                st.dataframe(df_summary, use_container_width=True)

                # --- Download Buttons ---
                proof_img_buf = generate_proof_image(results)
                
                btn_col1, btn_col2 = st.columns([1, 1])
                with btn_col1:
                    st.download_button(
                        label="📷 Download Summary Proof Image (PNG)",
                        data=proof_img_buf,
                        file_name=f"json_ld_audit_proof_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png",
                        mime="image/png",
                        type="primary"
                    )
                with btn_col2:
                    st.download_button(
                        label="📄 Download CSV Audit Report",
                        data=df_summary.to_csv(index=False),
                        file_name="json_syntax_audit.csv",
                        mime="text/csv"
                    )

                st.markdown("---")
                st.subheader("Detailed Diagnostic Breakdowns")

                for r in results:
                    badge = "🔴 SYNTAX ERROR" if r["syntax_errors"] else "🟢 VALID SYNTAX"
                    
                    with st.expander(f"{badge} — {r['url']} ({r['total_scripts']} JSON-LD blocks found)"):
                        if r["syntax_errors"]:
                            st.error("### ❌ JSON Syntax Errors Detected")
                            for err in r["syntax_errors"]:
                                st.markdown(f"**Block #{err['block_index']} Error:** `{err['error_message']}`")
                                if err["snippet"]:
                                    st.code(err["snippet"], language="text")
                                st.divider()

                        if r["valid_blocks"]:
                            st.success("### ✅ Valid JSON-LD Structures")
                            for block in r["valid_blocks"]:
                                st.markdown(f"**Block #{block['block_index']} (@type: `{block['type']}`)**")
                                st.json(block["data"])

            except Exception as err:
                st.error(f"Execution Error: {err}")
