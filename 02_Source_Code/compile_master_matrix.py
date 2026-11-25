#!/usr/bin/env python3
# ==============================================================================
# compile_master_matrix.py — Fixed Error-Safe Incremental Dashboard Suite
# ==============================================================================
import os
import json
import glob
import sys
import pandas as pd

if len(sys.argv) < 3:
    print("[❌] Pipeline Error: Missing parameters.")
    sys.exit(1)

RESULTS_DIR = sys.argv[1]
ACTIVE_RUN_ROOT = sys.argv[2]

OUTPUT_EXCEL = os.path.join(ACTIVE_RUN_ROOT, "APK_Security_Audit_Efficacy_Matrix.xlsx")
OUTPUT_INDEX_HTML = os.path.join(ACTIVE_RUN_ROOT, "matrix_report.html")
INDIVIDUAL_REPORTS_DIR = os.path.join(ACTIVE_RUN_ROOT, "reports")
GLOBAL_FALLBACK_INDEX = GLOBAL_FALLBACK_INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "matrix_report.html")

GROUND_TRUTH_FLAWS = {
    "ovaa": "CWE-926: Intent Redirection Security Threat",
    "insecurebankv2": "CWE-312: Sandbox SharedPreferences Data Leakage",
    "keepassdx": "CWE-226: Memory Native Cache Tracking Vulnerability",
    "thunderbird": "CWE-20: Unvalidated Protocol Stream Entry Point Flaw",
    "newpipe": "CWE-20: Media Validation Allocation Crash"
}

def compile_progressive_dashboard_system():
    summary_files = glob.glob(os.path.join(RESULTS_DIR, "*.summary.json"))
    if not summary_files: return

    os.makedirs(INDIVIDUAL_REPORTS_DIR, exist_ok=True)
    matrix_rows = []
    total_scanned_count = len(summary_files)

    for path in summary_files:
        try:
            with open(path, 'r') as f: item = json.load(f)
        except Exception: continue
            
        app_name = item.get("app_name", "Unknown")
        app_lower = app_name.lower()
        
        static_node = item.get("static", {})
        j_classes   = static_node.get("jadx", {}).get("java_files", 0)
        s_status    = static_node.get("semgrep", {}).get("status", "success")
        s_hits      = static_node.get("semgrep", {}).get("findings", 0)
        d_hits      = static_node.get("deps", {}).get("findings", 0)
        
        semgrep_raw_file = os.path.join(RESULTS_DIR, f"{app_name}.semgrep.json")
        detected_code_flaws = []
        if os.path.exists(semgrep_raw_file):
            try:
                with open(semgrep_raw_file, 'r') as sf:
                    s_data = json.load(sf)
                for res in s_data.get("results", []):
                    cwe = res.get("extra", {}).get("metadata", {}).get("cwe", "CWE-Unknown")
                    check_id = res.get("check_id", "security-issue")
                    line_no = res.get("start", {}).get("line", 0)
                    detected_code_flaws.append(f"⚠️ <b>[{cwe}]</b> {check_id} (Line: {line_no})")
            except Exception: pass
        if not detected_code_flaws: detected_code_flaws = ["None Registered / Secure Baseline Match"]
        else: detected_code_flaws = list(set(detected_code_flaws))

        sca_raw_file = os.path.join(RESULTS_DIR, f"{app_name}.deps.json")
        detected_sca_risks = []
        if os.path.exists(sca_raw_file):
            try:
                with open(sca_raw_file, 'r') as df:
                    d_data = json.load(df)
                for vuln in d_data.get("vulnerabilities", []):
                    v_id = vuln.get("vulnerability_id", "CVE-Unknown")
                    asset = vuln.get("component_asset", "artifact.jar")
                    detected_sca_risks.append(f"📦 <b>{v_id}</b> identified inside <code>{asset}</code>")
            except Exception: pass
        if not detected_sca_risks: detected_sca_risks = ["Zero Third-Party Library CVEs Found"]
        else: detected_sca_risks = list(set(detected_sca_risks[:10]))

        matched_profile = "Static General Audit Baseline Passed"
        for key, flaw in GROUND_TRUTH_FLAWS.items():
            if key in app_lower:
                matched_profile = flaw
                break

        individual_report_filename = f"{app_name}_detailed_report.html"
        individual_report_path = os.path.join(INDIVIDUAL_REPORTS_DIR, individual_report_filename)
        
        semgrep_html_list = "".join([f"<li>{flaw}</li>" for flaw in detected_code_flaws])
        sca_html_list = "".join([f"<li>{risk}</li>" for risk in detected_sca_risks])

        app_html_template = f"""<html>
<head><title>Vulnerability Report - {app_name}</title>
<style>
    body {{ font-family: Arial, sans-serif; margin: 40px; background: #f4f6f9; }}
    .container {{ max-width: 1000px; margin: 0 auto; background: #fff; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); border-radius: 6px; }}
    h2 {{ color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
    .back-btn {{ display: inline-block; padding: 10px 15px; background: #6c757d; color: white; text-decoration: none; border-radius: 4px; font-size: 13px; margin-bottom: 20px; }}
    ul {{ padding-left: 20px; }} li {{ margin-bottom: 8px; font-size: 13px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 25px; }}
    th {{ background: #343a40; color: white; padding: 10px; font-size: 13px; }}
    td {{ padding: 10px; border: 1px solid #dee2e6; font-size: 13px; font-weight: bold; text-align: center; }}
</style>
</head>
<body>
    <div class="container">
        <a href="../matrix_report.html" class="back-btn">⬅ Back to Master Uncluttered Index</a>
        <h2>🎯 Isolated Security Deep-Dive Target: {app_name}</h2>
        <table>
            <tr><th>Resolved Package ID</th><td>{item.get("package_name", "N/A")}</td><th>Execution Duration</th><td>{item.get("duration_sec", 0)}s</td></tr>
            <tr><th>Total Decompiled Classes</th><td>{j_classes}</td><th>Target Classification</th><td>{matched_profile}</td></tr>
            <tr><th>Semgrep Detections</th><td style="color:#d9534f;">{s_hits} Flaws</td><th>Supply-Chain CVEs</th><td style="color:#f0ad4e;">{d_hits} Leaks</td></tr>
        </table>
        <h3 style="color:#d9534f;">🚨 Custom Logic Flaws Map (Semgrep AST Findings)</h3><ul>{semgrep_html_list}</ul>
        <h3 style="color:#f0ad4e; margin-top:25px;">📦 Library Software Composition Analysis Risks</h3><ul>{sca_html_list}</ul>
    </div>
</body>
</html>"""
        with open(individual_report_path, "w", encoding="utf-8") as f:
            f.write(app_html_template)

        if s_status == "partially_processed":
            efficacy_text = "<span style='color:#721c24; background:#f8d7da; padding:4px 8px; border-radius:4px; font-weight:bold;'>⚠️ Semgrep Not Processed Fully</span>"
            action_link = f'<a href="#" onclick="alert(\'Execute snapshot string inside your console:\\n\\ncd {ACTIVE_RUN_ROOT} \\&\\& .\\/retry_{app_name}.sh\')" class="retry-btn">🔄 Retry Scan</a>'
        else:
            efficacy_text = "SCA Dominated (Supply-Chain Risks Heavy)" if d_hits > s_hits else ("Semgrep Code Rules Efficacious" if s_hits > 0 else "Static Baseline Verified")
            action_link = f'<a href="./reports/{individual_report_filename}" class="view-btn">🔗 View Detailed Report</a>'

        matrix_rows.append({
            "Target APK Identifier": app_name,
            "Resolved Android Package ID": item.get("package_name", "N/A"),
            "Execution Duration (Sec)": item.get("duration_sec", 0),
            "Total Decompiled Classes": j_classes,
            "Semgrep Static Hits": s_hits,
            "Software Supply-Chain CVEs": d_hits,
            "Algorithmic Tool Efficacy Assessment": efficacy_text,
            "Granular Code Auditing Interface": action_link
        })

    df_excel = pd.DataFrame(matrix_rows)
    excel_drop_cols = ["Algorithmic Tool Efficacy Assessment", "Granular Code Auditing Interface"]
    df_excel.drop(columns=[col for col in excel_drop_cols if col in df_excel.columns], errors='ignore').to_excel(OUTPUT_EXCEL, index=False)

    df_html = pd.DataFrame(matrix_rows)
    html_main_table = df_html.to_html(classes='table table-striped table-hover', border=1, justify='center', index=False, escape=False)

    html_index_template = f"""<html>
<head><title>Static Audit Master Index Suite</title>
<style>
    body {{ font-family: Arial, sans-serif; margin: 40px; background: #f4f6f9; zoom: 0.68 !important; transform-origin: top center; }}
    table.table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }}
    th {{ background: #007bff; color: white; padding: 12px; font-size: 13px; text-transform: uppercase; text-align: center; }}
    td {{ padding: 12px; text-align: center; border-bottom: 1px solid #dee2e6; font-size: 13px; }}
    tr:hover {{ background-color: #f1f3f5; }}
    
    .view-btn {{
        display: inline-block !important;
        white-space: nowrap !important;
        min-width: 175px !important;
        padding: 8px 14px !important;
        background: #28a745 !important;
        color: white !important;
        text-decoration: none !important;
        border-radius: 4px !important;
        font-weight: bold !important;
        font-size: 11px !important;
        text-align: center !important;
        box-sizing: border-box !important;
    }}
    .view-btn:hover {{ background: #218838 !important; }}
    
    .retry-btn {{
        display: inline-block !important;
        white-space: nowrap !important;
        min-width: 175px !important;
        padding: 8px 14px !important;
        background: #dc3545 !important;
        color: white !important;
        text-decoration: none !important;
        border-radius: 4px !important;
        font-weight: bold !important;
        font-size: 11px !important;
        text-align: center !important;
        box-sizing: border-box !important;
    }}
    .retry-btn:hover {{ background: #c82333 !important; }}

    #notification-toast {{
        display: none; position: fixed; top: 20px; left: 50%; transform: translateX(-50%);
        background: #ffc107; color: #212529; font-weight: bold; padding: 15px 30px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2); border-radius: 50px; z-index: 9999;
        font-size: 14px; border: 2px solid #e0a800; align-items: center; gap: 15px;
    }}
    .refresh-btn {{
        background: #212529; color: white; border: none; padding: 6px 12px;
        border-radius: 20px; cursor: pointer; font-weight: bold; font-size: 11px;
    }}
</style>
</head>
<body>
    <div id="notification-toast">
        🔔 Dashboard updated.. kindly refresh your dashboard window 
        <button class="refresh-btn" onclick="window.location.reload(true)">🔄 Refresh Now</button>
    </div>

    <h2>📊 Integrated Mobile Static Security Audit - Master Verification Dashboard</h2>
    <p class="sub">Continuous Integration Pipeline Metrics • Progressive Live Accumulation View Index</p>
    <p class="sub" style="color: #007bff; font-weight:bold;">Active Execution Isolation Path: {ACTIVE_RUN_ROOT}</p>
    
    <div id="table-container">
        {html_main_table}
    </div>
    <script>
        const initialRowCount = {total_scanned_count};
        setInterval(async () => {{
            try {{
                let response = await fetch(window.location.href, {{ cache: "no-store" }});
                let text = await response.text();
                let doc = new DOMParser().parseFromString(text, 'text/html');
                let foundRows = doc.querySelectorAll("table.table tbody tr").length;
                if (foundRows > initialRowCount) {{
                    document.getElementById("notification-toast").style.display = "flex";
                }}
            }} catch(e) {{ }}
        }}, 5000);
    </script>
</body>
</html>"""

    with open(OUTPUT_INDEX_HTML, "w", encoding="utf-8") as f:
        f.write(html_index_template)
    with open(GLOBAL_FALLBACK_INDEX, "w", encoding="utf-8") as f:
        f.write(html_index_template)
    print("[*] Incremental synchronization successful.")

if __name__ == "__main__":
    compile_progressive_dashboard_system()
