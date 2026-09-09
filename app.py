import subprocess
import sys
import time
import json
import io
from datetime import datetime
from urllib.parse import urlparse
import pandas as pd
import streamlit as st
from playwright.sync_api import sync_playwright

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend required for headless server environments
import matplotlib.pyplot as plt

# --- Safe Playwright Initialization ---
@st.cache_resource
def init_playwright_env():
    """Ensures Playwright executables exist without blocking Streamlit startup."""
    import os
    # Force Playwright to use standard cache directory in Streamlit Cloud
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "0"
    try:
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as err:
        st.error(f"Playwright browser installation failed: {err.stderr}")

init_playwright_env()


def locate_json_error(raw_str, error):
    """Pinpoints line number, column, and exact character snippet where JSON parsing failed."""
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
    """Generates a styled PNG image summary card as downloadable proof of auditing."""
    total = len(results)
    syntax_errors = sum(1 for r in results if r["syntax_errors"])
    clean_pages = total - syntax_errors
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Set up canvas height dynamically based on row count
    fig, ax = plt.subplots(figsize=(10, max(4, len(results) * 0.5 + 2.5)), dpi=150)
    ax.axis('off')

    # Header & Timestamp
    fig.text(0.05, 0.93, "JSON-LD Syntax Audit Proof", fontsize=18, fontweight='bold', color='#0F172A')
    fig.text(0.05, 0.88, f"Verified On: {timestamp}", fontsize=9, color='#64748B')

    # KPI Banner
    banner_text = f"Total Pages: {total}  |  Syntax Errors: {syntax_errors}  |  Valid Pages: {clean_pages}"
    fig.text(0.05, 0.81, banner_text, fontsize=11, fontweight='bold', color='#1E293B',
             bbox=dict(boxstyle="round,pad=0.5", facecolor="#F1F5F9", edgecolor="#CBD5E1"))

    # Table Formatting
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

    # Cell Styling & Badges
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

    # Save image to in-memory buffer
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', bbox_inches='tight', dpi=150)
    plt.close(fig)
    img_buffer.seek(0)
    return img_buffer


def inspect_page_structured_data(page, target_url):
    """Navigates to URL, extracts JSON-LD script tags, and audits strictly for JSON syntax errors."""
    report = {
        "url": target_url,
        "status_code": "Unknown",
        "total_scripts": 0,
        "has_errors": False,
        "syntax_errors": [],
        "valid_blocks": []
    }

    try:
        response = page.goto(target_url, wait_until="domcontentloaded", timeout=25000)
        time.sleep(1.5)
        report["status_code"] = response.status if response else "Failed"

        script_contents = page.evaluate("""() => {
            const scripts = document.querySelectorAll('script[type="application/ld+json"]');
            return Array.from(scripts).map((s, idx) => ({
                index: idx + 1,
                content: s.innerHTML
            }));
        }""")

        report["total_scripts"] = len(script_contents)

        if len(script_contents) == 0:
            report["has_errors"] = True
            report["syntax_errors"].append({
                "block_index": 0,
                "error_message": "No <script type='application/ld+json'> tags found on this page.",
                "snippet": ""
            })

        for item in script_contents:
            raw_json = item["content"].strip()
            block_idx = item["index"]

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
            "error_message": f"Failed to crawl page: {str(err)}",
            "snippet": ""
        })

    return report


def run_batch_audit(urls):
    """Executes headless Chromium scan across input URLs."""
    results = []
    progress_bar = st.progress(0)
    status_text = st.empty()
    total = len(urls)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu"
            ]
        )
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 800}
        )
        page = context.new_page()

        for idx, target_url in enumerate(urls):
            status_text.text(f"Auditing JSON Syntax ({idx + 1}/{total}): {target_url}")
            progress_bar.progress((idx + 1) / total)
            
            report = inspect_page_structured_data(page, target_url)
            results.append(report)

        browser.close()

    status_text.empty()
    progress_bar.empty()
    return results


# --- Streamlit UI Layout ---
st.set_page_config(page_title="JSON-LD Syntax Error Checker", layout="wide")
st.title("🏷️ JSON-LD Syntax Error Checker")
st.caption("Parses rendered page DOM via Chromium to detect broken JSON syntax, malformed tags, and parse errors.")

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
        with st.spinner("Extracting and validating JSON-LD syntax..."):
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

                # --- Download Buttons (CSV + Proof Image) ---
                proof_img_buf = generate_proof_image(results)
                
                btn_col1, btn_col2 = st.columns([1, 1])
                with btn_col1:
                    st.download_button(
                        label="📷 Download Summary as Proof Image (PNG)",
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
