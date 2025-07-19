import streamlit as st
import pandas as pd
import json
import os
import datetime
import requests
import plotly.graph_objects as go
from fpdf import FPDF
from email.message import EmailMessage
import smtplib
import base64
import time
import uuid
import re

try:
    import kaleido
    KALEIDO_READY = True
except ImportError:
    KALEIDO_READY = False

CONFIG_FILE = "configure.json"
APIKEYS_FILE = "apikeys.json"
SCANLOG_FILE = "scan_log.json"
LOGO_FILE = "dark_logo.png"

def load_json(path, default):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(default, f, indent=2)
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def clear_scan_history():
    save_json(SCANLOG_FILE, [])
    st.success("Scan history cleared.")

def get_api_keys():
    import streamlit as st
    try:
        if "apikeys" in st.secrets:
            # st.secrets['apikeys'] should be a dict-like mapping
            return dict(st.secrets["apikeys"])
    except Exception:
        pass
    # Fallback to file for local development
    return load_json(APIKEYS_FILE, {"VT": "", "AbuseIPDB": "", "Shodan": ""})

def get_credentials():
    try:
        # Use credentials from Streamlit Secrets if available
        if "credentials" in st.secrets:
            # st.secrets['credentials']['users'] is a list of dicts
            secret_users = st.secrets['credentials']['users']
            # Make sure we always return {"users": [...]}
            return {"users": [dict(u) for u in secret_users]}
    except Exception as e:
        pass  # Could log error here for local debugging if desired

    # Fallback to local file if running locally
    return load_json(CONFIG_FILE, {"users": [{"username": "admin", "password": "admin"}]})

def get_scanlog():
    log = load_json(SCANLOG_FILE, [])
    for entry in log:
        if 'scan_session' not in entry:
            entry['scan_session'] = entry.get('session', 'default')
    return log

def assign_risk_level(vt_malicious, abuse_score, abuse_whitelisted=False, abuse_confidence=0, ioc_type=None):
    vt = vt_malicious or 0
    abuse = abuse_score or 0
    # For IPs
    if ioc_type == "IP":
        if abuse_whitelisted or abuse_confidence == 0:
            return "Legitimate"
        if vt >= 10 or abuse >= 80:
            return "High"
        if 4 <= vt < 10 or 30 <= abuse < 80:
            return "Medium"
        if 1 <= vt < 4 or 1 <= abuse < 30:
            return "Low"
        return "Legitimate"
    else:  # Domain, URL, or Hash
        if vt >= 10:
            return "High"
        if 4 <= vt < 10:
            return "Medium"
        if 1 <= vt < 4:
            return "Low"
        return "Legitimate"

def scan_virustotal(ioc, api_key):
    if not api_key:
        return {"vt_malicious": 0, "error": "No VirusTotal API key found."}
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code != 200:
            # Include HTTP error/info if non-200
            return {"vt_malicious": 0, "error": f"VirusTotal HTTP error {r.status_code}: {r.text}"}
        data = r.json()
        if "data" in data and data["data"]:
            vt_base = data["data"][0]["attributes"]
            vt_stats = vt_base.get('last_analysis_stats', {})
            # Also include suspicious/undetected etc. for detail UI
            vt_results = vt_base.get('last_analysis_results', {})
            return {
                "vt_malicious": vt_stats.get("malicious", 0),
                "vt_suspicious": vt_stats.get("suspicious", 0),
                "vt_undetected": vt_stats.get("undetected", 0),
                "vt_data": vt_stats,
                "vt_results": vt_results,
            }
        return {"vt_malicious": 0, "vt_data": {}, "error": "No results found in VT for this IOC."}
    except Exception as e:
        return {"vt_malicious": 0, "error": f"VirusTotal error: {e}"}

def scan_abuseipdb(ip, api_key):
    if not api_key:
        return {"totalReports": 0}
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        js = r.json()
        return js.get('data', {"totalReports": 0})
    except Exception:
        return {"totalReports": 0}

def scan_shodan(ip, api_key):
    if not api_key:
        return {"error": "Shodan key missing"}
    try:
        import shodan
        api = shodan.Shodan(api_key)
        host = api.host(ip)
        return {"ports": host.get("ports", []), "org": host.get("org", "N/A")}
    except Exception as e:
        return {"error": str(e)}

def determine_ioc_type(ioc):
    ioc = ioc.strip()
    # Hashes
    if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
        return "MD5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
        return "SHA1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
        return "SHA256"
    # IPv4 (public or private)
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", ioc):
        return "IP"
    # IPv6
    if ':' in ioc and re.fullmatch(r"([a-fA-F0-9:]+)", ioc):
        return "IP"
    # URL (http/https)
    if re.match(r"^https?://", ioc, re.I):
        return "URL"
    # Domain
    if re.fullmatch(r"([A-Za-z0-9-]+\.)+[A-Za-z]{2,16}", ioc):
        return "Domain"
    # Defanged
    if "[.]" in ioc or "(.)" in ioc:
        return "Domain"  # or parse/clean before use!
    # Unknown type
    return "Unknown"

def new_scan_session():
    return f"{uuid.uuid4()}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

def log_scan_batch(batch_results, scan_session_id):
    scanlog = get_scanlog()
    for entry in batch_results:
        entry['scan_session'] = scan_session_id
        scanlog.append(entry)
    save_json(SCANLOG_FILE, scanlog)

def get_last_scan_session_id():
    log = get_scanlog()
    if not log:
        return None
    return log[-1]['scan_session']

def get_scan_results_by_session(scan_session_id):
    log = get_scanlog()
    return [e for e in log if e.get('scan_session') == scan_session_id]

def get_scan_sessions():
    log = get_scanlog()
    sessions = {}
    for e in log:
        s = e.get('scan_session')
        if s not in sessions:
            sessions[s] = []
        sessions[s].append(e)
    all_sessions = sorted(list(sessions.keys()), key=lambda k: max(pd.to_datetime(x['timestamp']) for x in sessions[k]), reverse=True)
    return [(k, sessions[k]) for k in all_sessions]

def create_risk_donut(stats):
    labels = ["High", "Medium", "Low", "Legitimate"]
    values = [stats.get("High", 0), stats.get("Medium", 0), stats.get("Low", 0), stats.get("Legitimate", 0)]
    colors = ['#ef4444', '#facc15', '#22c55e', '#6366f1']
    fig = go.Figure(data=[go.Pie(
        labels=labels, values=values, hole=.6, marker=dict(colors=colors),
        textinfo='label+percent', textfont=dict(size=18, color='white'), hoverinfo='label+value'
    )])
    fig.update_layout(showlegend=True, legend=dict(orientation="h", y=-0.14),
                      margin=dict(t=35, b=35, l=20, r=20),
                      paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='white'),
                      width=750, height=500)
    return fig

def create_bar_chart(df):
    col_name = 'vt_malicious' if 'vt_malicious' in df.columns else 'malicious'
    if col_name not in df.columns:
        df[col_name] = 0
    fig = go.Figure(data=[go.Bar(
        x=df["ioc"], y=df[col_name], marker_color='#2563eb', text=df[col_name], textposition='auto'
    )])
    fig.update_layout(
        title="VT Malicious Score", xaxis_title="IOC", yaxis_title="Malicious", width=950, height=450,
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='white'))
    return fig

def create_timeline(df):
    if 'timestamp' not in df.columns:
        return go.Figure()
    df['date'] = pd.to_datetime(df['timestamp'])
    df_count = df.groupby(df['date'].dt.date).size().reset_index(name='count')
    df_count['date'] = pd.to_datetime(df_count['date'])
    fig = go.Figure(data=go.Scatter(
        x=df_count['date'], y=df_count['count'], mode='lines+markers',
        line=dict(color='#2563eb', width=3), marker=dict(size=12, color='#3b82f6'),
        fill='tozeroy', fillcolor='rgba(37, 99, 235, 0.2)',
    ))
    fig.update_layout(
        title="Scan Activity",
        xaxis_title="Date", yaxis_title="Scans", width=950, height=425,
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='white'),
    )
    return fig

def generate_pdf_report(data, stats, donut_chart_path=None):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 19)
    pdf.set_text_color(37, 99, 235)
    pdf.cell(0, 17, "Threat Intel Aggregator Report", ln=True, align="C")
    pdf.ln(6)
    pdf.set_font("Arial", "", 12)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 11, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 13, "Summary:", ln=1)
    pdf.set_font("Arial", "", 11)
    for k in ["High","Medium","Low","Legitimate"]:
        pdf.cell(49, 10, f"{k}: {stats.get(k,0)}", ln=0)
    pdf.ln(13)
    if donut_chart_path and os.path.exists(donut_chart_path):
        pdf.image(donut_chart_path, w=120, h=85)
        pdf.ln(7)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(44, 11, "IOC", 1)
    pdf.cell(17, 11, "Type", 1)
    pdf.cell(22, 11, "VT", 1)
    pdf.cell(27, 11, "Abuse", 1)
    pdf.cell(32, 11, "Risk", 1)
    pdf.cell(44, 11, "Date", 1)
    pdf.ln()
    pdf.set_font("Arial", "", 11)
    for item in data:
        vt_score = item.get("vt", {}).get("vt_malicious", 0) if isinstance(item.get("vt"), dict) else 0
        abuse_score = item.get("abuse", {}).get("totalReports", 0) if isinstance(item.get("abuse"), dict) else 0
        pdf.cell(44, 8, str(item.get("ioc", ""))[:30], 1)
        pdf.cell(17, 8, str(item.get("type", "")), 1)
        pdf.cell(22, 8, str(vt_score), 1)
        pdf.cell(27, 8, str(abuse_score), 1)
        pdf.cell(32, 8, str(item.get("risk", "")), 1)
        pdf.cell(44, 8, str(item.get("timestamp", ""))[:19], 1)
        pdf.ln()
    fname = f"TI_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(fname)
    return fname

def send_email_report(recipient, report_file, sender, password):
    try:
        msg = EmailMessage()
        msg['Subject'] = 'Threat Intel Report'
        msg['From'] = sender
        msg['To'] = recipient
        msg.set_content('Please find attached the latest threat intelligence report.')
        with open(report_file, 'rb') as f:
            msg.add_attachment(f.read(), maintype='application', subtype='pdf', filename=report_file)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender, password)
            smtp.send_message(msg)
        return True
    except Exception as e:
        st.error(f"Email error: {e}")
        return False

def logout():
    for key in ["authenticated", "username", "page", "last_batch_id"]:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "username" not in st.session_state:
    st.session_state["username"] = ""
if "page" not in st.session_state:
    st.session_state["page"] = "Home"

def show_splash():
    with open(LOGO_FILE, "rb") as img_file:
        logo_b64 = base64.b64encode(img_file.read()).decode()
    st.markdown(
        f"""
        <style>
        body {{
            background: #000 !important;
        }}
        .splash-bg {{
            display: flex;
            justify-content: center;
            align-items: center;
            width: 100vw;
            height: 100vh;
            position: fixed !important;
            top: 0;
            left: 0;
            z-index: 99999;
            background: #000;
            margin: 0;
            padding: 0;
            overflow: hidden;
        }}
        .logo-aura {{
            width: 420px;
            height: 420px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            background: radial-gradient(
                circle at 50% 50%,
                rgba(59,130,246,0.50) 0%,
                rgba(37,99,235,0.24) 60%,
                rgba(59,130,246,0.08) 85%,
                transparent 95%
            );
            box-shadow: 0 0 90px 65px rgba(59,130,246,0.22);
        }}
        .splash-logo-img {{
            max-width: 320px;
            max-height: 320px;
            filter: drop-shadow(0 0 34px rgba(59,130,246,0.44));
            border-radius: 12%;
            opacity: 0;
            animation: fadeInPop 1s cubic-bezier(.22,.68,.44,1.09) 0.1s forwards;
        }}
        @keyframes fadeInPop {{
            0% {{ opacity: 0; transform: scale(0.94); }}
            45% {{ opacity: .33; transform: scale(1.10); }}
            90% {{ opacity: 0.96; transform: scale(1.025); }}
            100% {{ opacity: 1; transform: scale(1.0); }}
        }}
        </style>
        <div class="splash-bg">
          <div class="logo-aura">
            <img src="data:image/png;base64,{logo_b64}" class="splash-logo-img" alt="ThreatIntel Logo"/>
          </div>
        </div>
        """,
        unsafe_allow_html=True
    )

def show_login():
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        st.markdown(f"""<div style="display:flex;flex-direction:column;align-items:center;">
                <img src="data:image/png;base64,{base64.b64encode(open(LOGO_FILE,"rb").read()).decode()}" width="95" style="margin-bottom:18px;">
                <h2 style="text-align:center;">Threat Intel Aggregator</h2>
            </div>
        """, unsafe_allow_html=True)
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login", use_container_width=True)
            if submitted:
                credentials = get_credentials()
                for user in credentials.get("users", []):
                    if user.get("username") == username and user.get("password") == password:
                        st.session_state["authenticated"] = True
                        st.session_state["username"] = username
                        st.rerun()
                st.error("Invalid username or password")

def show_sidebar():
    with st.sidebar:
        st.image(LOGO_FILE, width=75)
        st.title("Threat Intel")
        st.caption(f"User: {st.session_state['username']}")
        st.markdown("---")
        pages = {
            "🏠 Dashboard": "Home",
            "🔍 Manual IOC Scan": "Manual",
            "📂 Batch Scanning": "Batch",
            "📊 Results": "Results",
            "📜 Scan History": "History",
            "📈 Charts & Analytics": "Charts",
            "📑 Reports": "Report",
            "⚙️ Settings": "Settings",
            "🚪 Logout": "Logout"
        }
        for label, page in pages.items():
            if st.button(label, use_container_width=True, key=f"btn_{page}"):
                st.session_state["page"] = page
                if page == "Logout":
                    logout()

def show_home():
    st.markdown("""
        <h1 style="text-align:center;color:#2563eb;margin-bottom:20px;">Threat Intelligence Dashboard</h1>
    """, unsafe_allow_html=True)
    scan_sessions = get_scan_sessions()
    if scan_sessions:
        recent_id, recent_results = scan_sessions[0]
        st.session_state["last_batch_id"] = recent_id
        show_count = len(recent_results)
        risk_counts = {"High":0,"Medium":0,"Low":0,"Legitimate":0}
        for item in recent_results:
            risk = item.get("risk", "Legitimate")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
    else:
        show_count = 0
        risk_counts = {"High":0,"Medium":0,"Low":0,"Legitimate":0}
        recent_results = []

    col1, col2, col3, col4 = st.columns(4)
    stats_list = [
      ("Recent Scanned", show_count,"#2563eb"),
      ("High", risk_counts["High"],"#ef4444"),
      ("Medium", risk_counts["Medium"],"#facc15"),
      ("Low", risk_counts["Low"],"#22c55e")
    ]
    for (k, v, c), col in zip(stats_list, [col1, col2, col3, col4]):
        col.markdown(f"""
            <div style="background-color:#1e293b;padding:16px;border-radius:10px;text-align:center;">
                <h3 style="margin:0;color:#e2e8f0;font-size:16px;">{k}</h3>
                <p style="font-size:28px;font-weight:bold;margin:8px 0;color:{c};">{v}</p>
            </div>
        """, unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Risk Distribution (Recent)")
        st.plotly_chart(create_risk_donut(risk_counts), use_container_width=False)
    with col2:
        st.subheader("Recent Activity Timeline")
        if recent_results:
            df = pd.DataFrame(recent_results)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            st.plotly_chart(create_timeline(df), use_container_width=False)

    st.subheader("Recent Scans")
    if recent_results:
        df = pd.DataFrame(recent_results)
        df['vt_malicious'] = df['vt'].apply(lambda x: x.get('vt_malicious', 0) if isinstance(x, dict) else 0)
        df['abuse_reports'] = df['abuse'].apply(lambda x: x.get('totalReports', 0) if isinstance(x, dict) else 0)
        display_cols = ['timestamp', 'ioc', 'type', 'risk', 'vt_malicious', 'abuse_reports']
        df_display = df[display_cols].head(7)
        st.dataframe(df_display, use_container_width=True)
    st.markdown("### Quick Actions")
    col1, col2, col3 = st.columns(3)
    if col1.button("🔍 New IOC Scan"):
        st.session_state["page"] = "Manual"
        st.rerun()
    if col2.button("📂 Batch Scan"):
        st.session_state["page"] = "Batch"
        st.rerun()
    if col3.button("📊 View Results"):
        st.session_state["page"] = "Results"
        st.rerun()

def show_manual_scan():
    st.title("Manual IOC Scan")

    ioc = st.text_input("Enter IP, Domain, or URL:", placeholder="8.8.8.8, example.com, etc.")
    api_keys = get_api_keys()

    if st.button("Run Scan"):
        st.markdown("---")
        ioc_t = determine_ioc_type(ioc)
        vt_result = scan_virustotal(ioc, api_keys.get("VT"))
        abuse_result = scan_abuseipdb(ioc, api_keys.get("AbuseIPDB")) if ioc_t == "IP" else {"totalReports": 0}
        shodan_result = scan_shodan(ioc, api_keys.get("Shodan")) if ioc_t == "IP" else None

        vt_malicious = vt_result.get("vt_malicious", 0)
        abuse_reports = abuse_result.get("totalReports", 0)
        abuse_whitelisted = abuse_result.get("isWhitelisted", False)
        abuse_confidence = abuse_result.get("abuseConfidenceScore", 0)
        risk = assign_risk_level(
            vt_malicious, abuse_reports, abuse_whitelisted, abuse_confidence, ioc_t
        )

        scan_session = new_scan_session()
        result = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ioc": ioc,
            "type": ioc_t,
            "vt": vt_result,
            "abuse": abuse_result,
            "shodan": shodan_result,
            "risk": risk,
            "scan_session": scan_session
        }
        log_scan_batch([result], scan_session)
        st.session_state["last_batch_id"] = scan_session

        # Error display
        if "error" in vt_result:
            st.warning(f"VirusTotal error: {vt_result['error']}")
        if "error" in abuse_result:
            st.warning(f"AbuseIPDB error: {abuse_result['error']}")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""<div style="background-color:#1e293b;padding:18px;border-radius:10px;">
                <h3 style="margin:0;color:white;font-size:18px;">{ioc}</h3>
                <span style="font-size:16px;color:#94a3b8;">Type: {ioc_t} <br>Risk: 
                    <b style="color:{'#ef4444' if risk=='High' else '#facc15' if risk=='Medium' else '#22c55e' if risk=='Low' else '#6366f1'};">{risk}</b>
                </span>
            </div>""", unsafe_allow_html=True)
        with col2:
            st.markdown(
                f"""<div style="background-color:#1e293b;padding:18px;border-radius:10px;">
                <b>VirusTotal Malicious:</b> {vt_malicious}<br>
                <b>AbuseIPDB:</b> {abuse_reports}
                </div>""", unsafe_allow_html=True)

        st.markdown("#### Details")
        with st.expander("VirusTotal Details"):
            # Show top 5 positive vendors if available
            vt_results = vt_result.get("vt_results", {})
            positives = []
            for vendor, res in vt_results.items():
                if res.get("category") in ("malicious", "suspicious"):
                    positives.append((vendor, res.get("result")))
            if positives:
                st.write("**Top Detections:**")
                for v, r in positives[:5]:
                    st.markdown(f"`{v}` : **{r}**")
            st.json(vt_result)
        with st.expander("AbuseIPDB Details"):
            st.json(abuse_result)
        if shodan_result is not None:
            with st.expander("Shodan Details"):
                st.json(shodan_result)

def show_batch_scan():
    st.title("Batch CSV Scan")
    uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            text_cols = df.select_dtypes(include=['object']).columns.tolist()
            if not text_cols:
                st.error("No suitable IOC column found.")
            else:
                selected_column = st.selectbox("Select IOC column", text_cols)
                if st.button("Start Batch Scan", use_container_width=True):
                    iocs_to_scan = df[selected_column].dropna().unique()
                    total_iocs = len(iocs_to_scan)
                    if total_iocs == 0:
                        st.error("No valid IOCs found in the selected column.")
                    else:
                        api_keys = get_api_keys()
                        progress_bar = st.progress(0)
                        scan_status = st.empty()
                        results = []
                        scan_session = new_scan_session()
                        for i, ioc in enumerate(iocs_to_scan):
                            scan_status.info(f"Scanning: {ioc} ({i+1}/{total_iocs})")
                            ioc_t = determine_ioc_type(ioc)
                            vt_result = scan_virustotal(ioc, api_keys.get("VT"))
                            abuse_result = scan_abuseipdb(ioc, api_keys.get("AbuseIPDB")) if ioc_t == "IP" else {"totalReports": 0}
                            vt_malicious = vt_result.get("vt_malicious", 0)
                            abuse_reports = abuse_result.get("totalReports", 0)
                            abuse_whitelisted = abuse_result.get("isWhitelisted", False)
                            abuse_confidence = abuse_result.get("abuseConfidenceScore", 0)
                            risk = assign_risk_level(
                                vt_malicious, abuse_reports, abuse_whitelisted, abuse_confidence, ioc_t
                            )
                            result = {
                                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "ioc": ioc,
                                "type": ioc_t,
                                "vt": vt_result,
                                "abuse": abuse_result,
                                "risk": risk,
                                "scan_session": scan_session
                            }
                            results.append(result)
                            progress_bar.progress((i + 1) / total_iocs)

                        log_scan_batch(results, scan_session)
                        st.session_state["last_batch_id"] = scan_session
                        scan_status.success(f"Completed scanning {total_iocs} IOCs.")

                        results_df = pd.DataFrame(results)
                        results_df['vt_malicious'] = results_df['vt'].apply(lambda x: x.get('vt_malicious', 0))
                        results_df['abuse_reports'] = results_df['abuse'].apply(lambda x: x.get('totalReports', 0))
                        show_color = {'High': '#fecaca', 'Medium': '#fef9c3', 'Low': '#d1fae5', 'Legitimate': '#e0e7ff'}
                        st.dataframe(
                            results_df[['timestamp','ioc','type','risk','vt_malicious','abuse_reports']].style.apply(
                                lambda row: ['background-color: {}'.format(show_color.get(row.risk,'')) if col == 'risk' else '' for col in row.index], axis=1
                            ),
                            use_container_width=True)
                        st.download_button(
                            "Download Results CSV",
                            results_df.to_csv(index=False).encode('utf-8'),
                            f"batch_scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            "text/csv"
                        )
        except Exception as e:
            st.error(f"Error processing the CSV file: {str(e)}")

def show_results():
    st.title("Results (Latest Scan)")
    last_id = st.session_state.get("last_batch_id", get_last_scan_session_id())
    if not last_id:
        st.info("No scan results found.")
        return
    results = get_scan_results_by_session(last_id)
    if not results:
        st.info("No scan results for current session; run a scan or select from Scan History.")
        return
    df = pd.DataFrame(results)
    df['vt_malicious'] = df['vt'].apply(lambda x: x.get('vt_malicious', 0) if isinstance(x, dict) else 0)
    df['abuse_reports'] = df['abuse'].apply(lambda x: x.get('totalReports', 0) if isinstance(x, dict) else 0)

    # --- Summary Table with color-coded risk ---
    def highlight_risk(row):
        color = {
            "High": "background-color: #fecaca;",
            "Medium": "background-color: #fef9c3;",
            "Low": "background-color: #d1fae5;",
            "Legitimate": "background-color: #e0e7ff;",
        }.get(row["risk"], "")
        return [color if col == "risk" else "" for col in row.index]

    st.subheader("Summary Table")
    st.dataframe(
        df[['timestamp','ioc','type','risk','vt_malicious','abuse_reports']].style.apply(highlight_risk, axis=1),
        use_container_width=True
    )
    st.download_button(
        "Download Results CSV",
        df.to_csv(index=False).encode('utf-8'),
        f"scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        "text/csv"
    )
    st.markdown("---")

    st.subheader("Full Details for Each Result")
    for i, row in df.iterrows():
        ioc = row['ioc']
        risk = row['risk']
        vt_result = row['vt'] if 'vt' in row and isinstance(row['vt'], dict) else {}
        abuse_result = row['abuse'] if 'abuse' in row and isinstance(row['abuse'], dict) else {}
        shodan_result = row.get('shodan', None) if 'shodan' in row else None

        with st.expander(f"{ioc} | Risk: {risk} | Type: {row['type']} | Scanned: {row['timestamp']}"):
            st.markdown(f"**IOC:** `{ioc}` | **Risk**: `{risk}` | **Type**: `{row['type']}` | **Timestamp**: {row['timestamp']}")
            st.markdown("#### VirusTotal Details (full)")
            st.json(vt_result)
            st.markdown("#### AbuseIPDB Details (full)")
            st.json(abuse_result)
            if shodan_result and isinstance(shodan_result, dict):
                st.markdown("#### Shodan Details (full)")
                st.json(shodan_result)

            # Optional: transparency or warnings for 0/clean/unknown
            vt_mal = row['vt_malicious']
            abuse_sc = row['abuse_reports']
            abuse_whitelisted = abuse_result.get("isWhitelisted", False)
            abuse_confidence = abuse_result.get("abuseConfidenceScore", 0)
            if (risk == "Legitimate") and vt_mal == 0 and abuse_sc == 0:
                st.info("Not present in threat feeds as of scan time. Malicious IOCs may evade detection until widely reported.")

def show_charts():
    st.title("Charts & Analytics (Latest Scan)")
    last_id = st.session_state.get("last_batch_id", get_last_scan_session_id())
    results = get_scan_results_by_session(last_id) if last_id else []
    if not results:
        st.info("No scan data for charts.")
        return
    df = pd.DataFrame(results)
    df['vt_malicious'] = df['vt'].apply(lambda x: x.get('vt_malicious', 0) if isinstance(x, dict) else 0)
    df['abuse_reports'] = df['abuse'].apply(lambda x: x.get('totalReports', 0) if isinstance(x, dict) else 0)
    risk_counts = df['risk'].value_counts().to_dict()
    st.subheader("Risk Distribution")
    st.plotly_chart(create_risk_donut(risk_counts), use_container_width=False)
    st.subheader("Malicious Score (VT)")
    st.plotly_chart(create_bar_chart(df.sort_values('vt_malicious',ascending=False).head(10)), use_container_width=False)
    st.subheader("Scan Timeline")
    st.plotly_chart(create_timeline(df), use_container_width=False)

def show_report():
    st.title("Report (Latest Scan)")
    last_id = st.session_state.get("last_batch_id", get_last_scan_session_id())
    results = get_scan_results_by_session(last_id) if last_id else []
    if not results:
        st.info("No data for report.")
        return
    stats = {"High":0,"Medium":0,"Low":0,"Legitimate":0}
    for item in results:
        stats[item.get("risk","Legitimate")] = stats.get(item.get("risk","Legitimate"), 0) + 1
    donut_fig = create_risk_donut(stats)
    img_path = "donut_chart_tmp.png"
    donut_img_made = False
    if KALEIDO_READY:
        try:
            donut_fig.write_image(img_path, width=700, height=375)
            donut_img_made = True
        except Exception:
            donut_img_made = False
    report_file = generate_pdf_report(results, stats, donut_chart_path=img_path if donut_img_made else None)
    with open(report_file, "rb") as f:
        st.download_button("Download PDF Report", f, file_name=report_file, mime="application/pdf")
    if donut_img_made:
        st.image(img_path, caption="Risk Distribution", width=650)
    st.markdown("**Preview Table**")
    df = pd.DataFrame(results)
    df['vt_malicious'] = df['vt'].apply(lambda x: x.get('vt_malicious', 0) if isinstance(x, dict) else 0)
    df['abuse_reports'] = df['abuse'].apply(lambda x: x.get('totalReports', 0) if isinstance(x, dict) else 0)
    st.dataframe(df[['timestamp','ioc','type','risk','vt_malicious','abuse_reports']], use_container_width=True)
    with st.expander("Send PDF report via email"):
        email_recipient = st.text_input("Recipient Email")
        sender_email = st.text_input("Your Gmail Address")
        sender_password = st.text_input("App Password", type="password")
        if st.button("Send Email"):
            if email_recipient and sender_email and sender_password:
                with st.spinner("Sending email..."):
                    if send_email_report(email_recipient, report_file, sender_email, sender_password):
                        st.success(f"Email sent to {email_recipient}")
                    else:
                        st.error("Failed to send email. Check credentials")
            else:
                st.error("Please fill in all email fields")

def show_history():
    st.title("Scan History (All)", help="Browse all scan batches and get specific reports.")
    all_sessions = get_scan_sessions()
    if not all_sessions:
        st.info("No scan history yet.")
        return
    
    if st.button("🗑️ Clear All Scan History", help="Remove all previous scans and start fresh."):
        clear_scan_history()
        st.rerun()

    data = []
    session_labels = []
    display_sessions = []
    for sid, batch in all_sessions:
        if batch:
            dt = max([pd.to_datetime(e["timestamp"]) for e in batch])
            session_labels.append(f"{dt.strftime('%Y-%m-%d %H:%M:%S')} ({len(batch)} scans)")
            data.append(batch)
            display_sessions.append((sid, dt, len(batch)))
    df_meta = pd.DataFrame(display_sessions, columns=["session_id","datetime","n_scans"])
    latest = st.button("Show Latest Scan")
    pick = st.radio(
        "Pick scan batch to view details/report:", session_labels, index=0
    )
    sel_i = session_labels.index(pick)
    batch = data[sel_i]
    if st.button("Get Report For This Scan"):
        st.session_state["last_batch_id"] = all_sessions[sel_i][0]
        st.session_state["page"] = "Report"
        st.rerun()
    # Filter and sort
    sort = st.selectbox("Sort by", ["Newest", "Oldest"])
    show_date = st.date_input("Show scans after", value=None)
    batch_df = pd.DataFrame(batch)
    batch_df['vt_malicious'] = batch_df['vt'].apply(lambda x: x.get('vt_malicious', 0) if isinstance(x, dict) else 0)
    batch_df['abuse_reports'] = batch_df['abuse'].apply(lambda x: x.get('totalReports', 0) if isinstance(x, dict) else 0)
    batch_df['timestamp'] = pd.to_datetime(batch_df['timestamp'])
    if show_date:
        batch_df = batch_df[batch_df['timestamp'].dt.date >= show_date]
    if sort == "Newest":
        batch_df = batch_df.sort_values("timestamp", ascending=False)
    else:
        batch_df = batch_df.sort_values("timestamp", ascending=True)
    st.dataframe(batch_df[['timestamp','ioc','type','risk','vt_malicious','abuse_reports']], use_container_width=True)

def show_settings():
    st.title("Settings & Info")
    api_keys = get_api_keys()
    with st.form("api_settings"):
        vt_key = st.text_input("VirusTotal API Key", value=api_keys.get("VT", ""))
        abuse_key = st.text_input("AbuseIPDB API Key", value=api_keys.get("AbuseIPDB", ""))
        shodan_key = st.text_input("Shodan API Key", value=api_keys.get("Shodan", ""))
        submit = st.form_submit_button("Save Settings")
    if submit:
        new_keys = {"VT": vt_key, "AbuseIPDB": abuse_key, "Shodan": shodan_key}
        save_json(APIKEYS_FILE, new_keys)
        st.success("Settings saved. Refreshing...")
        st.rerun()
    with st.expander("About This Threat Intel Dashboard", expanded=True):
        st.markdown("""
        <b>About:</b> This tool is for threat intelligence analysts, SOC teams, or anyone needing IOC aggregation, reporting, and monitoring.<br>
        <b>Developed For:</b> Security teams needing fast risk verdicts, modern analytics, instant audit/report generation.<br>
        <b>What you can do:</b>
        - Query VirusTotal, AbuseIPDB, and Shodan for IPs, domains, URLs
        - Batch scan or single-scan, with full risk breakdowns
        - Instantly visualize with pro charts (donut, timeline, bars)
        - Download or email pro reports (PDF)
        - Search, filter, and manage scan history
        - Update API credentials easily
        <br><br>
        <b>Version:</b> 1.0 | <b>Created:</b> July 2025
        """, unsafe_allow_html=True)
        st.caption("Purpose: Help cyber teams unify threat scanning/reporting in one modern browser app.")
    st.markdown("---")
    st.write("Support: support@example.com")

# ---- APP ENTRY (SPLASH/LOGIN/HOME)
def app():
    if "show_splash" not in st.session_state:
        st.session_state["show_splash"] = True
        show_splash()
        st.rerun()
    elif st.session_state["show_splash"]:
        show_splash()
        time.sleep(2)
        st.session_state["show_splash"] = False
        st.rerun()
    elif not st.session_state["authenticated"]:
        show_login()
    else:
        show_sidebar()
        page = st.session_state["page"]
        if page == "Home": show_home()
        elif page == "Manual": show_manual_scan()
        elif page == "Batch": show_batch_scan()
        elif page == "Results": show_results()
        elif page == "Charts": show_charts()
        elif page == "History": show_history()
        elif page == "Report": show_report()
        elif page == "Settings": show_settings()

st.markdown("""
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}
h1,h2,h3 {color:#2563eb !important;}
.block-container {padding-top: 1rem;}
.stButton button {background-color: #2563eb; color: white;}
.stButton button:hover {background-color: #1d4ed8; color: white;}
body {background: #0e1117;}
div[data-testid="stVerticalBlock"] {gap: 0.5rem;}
</style>
""", unsafe_allow_html=True)

app()
