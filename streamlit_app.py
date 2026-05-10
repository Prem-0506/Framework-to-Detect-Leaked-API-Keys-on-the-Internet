import re
import requests
import streamlit as st
import math
from collections import Counter
import pandas as pd
from datetime import datetime

st.set_page_config(page_title="API Key Leak Detector", layout="wide")

st.title("🔍 API Key Leak Detector")

# ---------------- SIDEBAR NAVIGATION ----------------
st.sidebar.title("🔍 Navigation")
page = st.sidebar.radio("Go to", ["Text Scanner", "File Scanner", "GitHub Scanner", "PasteBin Scanner"])

# ---------------- REGEX PATTERNS ----------------
patterns = [
    # ---------------- AWS ----------------
    {"provider": "AWS", "type": "API Key", "pattern": r"AKIA[0-9A-Z]{16}"},

    # ---------------- OPENAI ----------------
    {"provider": "OpenAI", "type": "Secret Key", "pattern": r"sk-[a-zA-Z0-9]{32,}"},

    # ---------------- GCP ----------------
    {"provider": "GCP", "type": "API Key", "pattern": r"AIza[0-9A-Za-z\-_]{35}"},

    # ---------------- AZURE ----------------
    {"provider": "Azure", "type": "API Key", 
     "pattern": r"(?i)(azure|key|secret)[\"'\s:=]+([a-f0-9]{32})"},
    {"provider": "Azure", "type": "Storage Key", 
     "pattern": r"[A-Za-z0-9+/]{88}=="},

    # ---------------- STRIPE ----------------
    {"provider": "Stripe", "type": "Secret Key", 
     "pattern": r"sk_live_[0-9a-zA-Z]{24}"},
    {"provider": "Stripe", "type": "Publishable Key", 
     "pattern": r"pk_live_[0-9a-zA-Z]{24}"},

    # ---------------- SLACK ----------------
    {"provider": "Slack", "type": "Access Token", 
     "pattern": r"xox[baprs]-[0-9a-zA-Z\-]{10,48}"},

    # ---------------- TWILIO ----------------
    {"provider": "Twilio", "type": "API Key", 
     "pattern": r"SK[0-9a-fA-F]{32}"},
    {"provider": "Twilio", "type": "Account SID", 
     "pattern": r"AC[0-9a-fA-F]{32}"},

    # ---------------- PAYPAL ----------------
    {"provider": "PayPal", "type": "Access Token", 
     "pattern": r"A21AA[a-zA-Z0-9\-_]{20,}"},

    # ---------------- BRAINTREE ----------------
    {"provider": "Braintree", "type": "Access Token", 
     "pattern": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"},

    # ---------------- SHOPIFY ----------------
    {"provider": "Shopify", "type": "Access Token", 
     "pattern": r"shpat_[0-9a-fA-F]{32}"},
    {"provider": "Shopify", "type": "API Key", 
     "pattern": r"shpca_[0-9a-fA-F]{32}"},

    # ---------------- GENERIC ----------------
    {"provider": "Generic", "type": "Token", 
     "pattern": r"(?i)(api[_-]?key|token|secret)[\"'\s:=]+([A-Za-z0-9_\-]{20,})"},

    {"provider": "Generic", "type": "Password", 
     "pattern": r"(?i)password\s*=\s*[\"']([^\"']+)[\"']"},
    {"provider": "Unknown", "type": "Possible Key",
     "pattern": r"[A-Za-z0-9_\-]{16,}"}
]

# ---------------- ENTROPY FUNCTION ----------------
def calculate_entropy(data):
    if not data:
        return 0
    counter = Counter(data)
    length = len(data)

    entropy = 0
    for count in counter.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return entropy

# ---------------- SEVERITY ----------------
def classify_severity(key, key_type):
    entropy = calculate_entropy(key)

    if key_type in ["Secret Key", "Access Token", "Password"]:
        severity = "HIGH"
    elif key_type in ["API Key", "Auth Token"]:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return severity, round(entropy, 2)

# ---------------- RISK SCORE ----------------
def calculate_risk_score(severity, entropy):
    base = 80 if severity == "HIGH" else 50 if severity == "MEDIUM" else 20
    return min(100, int(base + entropy * 5))

# ---------------- MASK ----------------
def mask_key(key):
    return key[:4] + "****" + key[-4:]

# ---------------- NOTIFICATION ----------------
def send_notification(leak):
    return {
        "recipient": "developer@example.com",
        "type": leak["type"],
        "risk": leak["risk_score"],
        "status": "SENT (MOCK)",
        "time": leak["timestamp"]
    }

# ---------------- DETECTION ----------------
def detect_keys(text, source="Unknown"):
    results = []
    seen_keys = set()

    for item in patterns:
        provider = item["provider"]
        key_type = item["type"]
        pattern = item["pattern"]

        matches = re.findall(pattern, text)

        for match in matches:
            if isinstance(match, tuple):
                key_value = next((m for m in match if m), "")
            else:
                key_value = match

            if key_value in seen_keys:
                continue

            seen_keys.add(key_value)

            severity, entropy = classify_severity(key_value, key_type)

            risk = calculate_risk_score(severity, entropy)

            results.append({
                "source": source,
                "provider": provider,   # 🔥 NEW COLUMN
                "type": key_type,
                "key": mask_key(key_value),
                "severity": severity,
                "entropy": entropy,
                "risk_score": risk,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

    return results, []

# ---------------- DASHBOARD ----------------
def show_dashboard(results, notifications):
    df = pd.DataFrame(results)

    st.error(f"⚠ Found {len(df)} exposed secrets!")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Exposures", len(df))
    col2.metric("High Risk", len(df[df["risk_score"] > 75]))
    col3.metric("Avg Risk Score", int(df["risk_score"].mean()))

    st.subheader("📋 Exposure Dashboard")

    def color_risk(val):
        if val > 75:
            return "background-color: red; color: white"
        elif val > 50:
            return "background-color: orange"
        else:
            return "background-color: green"

    st.dataframe(df.style.map(color_risk, subset=["risk_score"]), use_container_width=True)

    # Charts
    st.subheader("📊 Risk Score Distribution")
    st.bar_chart(df["risk_score"])

    st.subheader("🔑 API Key Type Distribution")
    st.bar_chart(df["type"].value_counts())

    st.subheader("🌐 Provider Distribution")
    st.bar_chart(df["provider"].value_counts())

    # Notifications
    if notifications:
        st.subheader("🔔 Automated Alerts")
        st.dataframe(pd.DataFrame(notifications))

        for n in notifications:
            st.warning(f"🚨 Alert sent for {n['type']} (Risk: {n['risk']})")

# ---------------- GITHUB RAW FIX ----------------
def convert_to_raw(url):
    if "github.com" in url and "blob" in url:
        url = url.replace("github.com", "raw.githubusercontent.com")
        url = url.replace("/blob/", "/")
    if "pastebin.com/" in url and "/raw/" not in url:
        paste_id = url.split("/")[-1]
        url = f"https://pastebin.com/raw/{paste_id}"
    return url

# ---------------- COMMON SCAN ----------------
def run_scan(data, source):
    if not data:
        st.warning("No data provided")
        return

    results, notifications = detect_keys(data, source)

    if results:
        show_dashboard(results, notifications)
    else:
        st.success("✅ No API keys detected")

# ---------------- PAGE: TEXT ----------------
if page == "Text Scanner":
    st.header("📝 Scan Text")
    text_data = st.text_area("Paste your code/text here")

    if st.button("Scan Text"):
        run_scan(text_data, "Text Input")

# ---------------- PAGE: FILE ----------------
elif page == "File Scanner":
    st.header("📁 Scan File")
    file = st.file_uploader("Upload a file")

    if file:
        data = file.read().decode("utf-8")
        if st.button("Scan File"):
            run_scan(data, "File Upload")

# ---------------- PAGE: GITHUB ----------------
elif page == "GitHub Scanner":
    st.header("🌐 Scan GitHub File")

    url = st.text_input("Enter GitHub URL")

    if st.button("Scan GitHub"):
        if url:
            try:
                url = convert_to_raw(url)
                response = requests.get(url)
                data = response.text
                run_scan(data, "GitHub")
            except:
                st.error("Failed to fetch URL")
        else:
            st.warning("Enter a GitHub URL")
elif page == "PasteBin Scanner":
    st.header("📋 Scan PasteBin")

    url = st.text_input("Enter PasteBin URL")

    if st.button("Scan PasteBin"):
        if url:
            try:
                url = convert_to_raw(url)
                response = requests.get(url)
                data = response.text
                run_scan(data, "PasteBin")
            except:
                st.error("Failed to fetch URL")
        else:
            st.warning("Enter a PasteBin URL")

# ---------------- SIDEBAR ABOUT ----------------
st.sidebar.markdown("---")
st.sidebar.title("About")
st.sidebar.write("""
🔐 API Key Leak Detector

This is an advanced tool designed to scan for exposed API keys and secrets across multiple sources. It uses regex patterns to identify potential leaks, calculates entropy for risk assessment, and provides a clean dashboard for visualization.
In this website, the top 10 types of API Keys will be detected and the seveirity of the leak will be classified as HIGH, MEDIUM, or LOW based on the type of key and its entropy. A risk score is calculated to help prioritize remediation efforts. The dashboard provides insights into the detected leaks and mock notifications for alerts.

Features:
- Multi-source scanning
- Entropy-based detection
- Risk scoring
- Automated alerts (mock)
- Clean dashboard

Built for CTF Hackathon 🚀
""")