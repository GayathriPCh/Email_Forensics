import streamlit as st
from email_parser import parse_email
from ip_geolocation import get_ip_info, extract_ips
from phishing_detector import detect_phishing_indicators
from report_generator import generate_report
import pandas as pd
import json

def main():
    st.set_page_config(page_title="Email Forensics Tool", page_icon="🔍", layout="wide")

    st.title("📧 Email Forensics: Phishing Analysis & IP Tracking")

    st.sidebar.title("📘 About")
    st.sidebar.markdown("""
    This tool parses raw email headers or `.eml` files, detects phishing attempts,
    and visualizes IP trails via geolocation.
    """)

    # Accept input via textarea or upload
    input_method = st.radio("Choose input method:", ["Paste raw headers", "Upload .eml file"])

    raw_email = ""
    if input_method == "Paste raw headers":
        raw_email = st.text_area("📩 Paste raw email headers here", height=250)
    else:
        uploaded_file = st.file_uploader("Upload an .eml file", type=["eml", "txt"])
        if uploaded_file is not None:
            raw_email = uploaded_file.read().decode("utf-8", errors="ignore")

    if st.button("🚀 Analyze Email"):
        if not raw_email.strip():
            st.warning("Please provide email input first.")
            return

        with st.spinner("Analyzing..."):
            email_data = parse_email(raw_email)
            indicators, score = detect_phishing_indicators(email_data)
            report = generate_report(email_data, indicators, score)
            ips = extract_ips(email_data.get('Received', []))
            ip_info = {ip: get_ip_info(ip) for ip in ips}

        st.subheader("📬 Parsed Email Headers")
        st.json(email_data)

        st.subheader("⚠️ Phishing Indicators")
        if indicators:
            st.error(f"{len(indicators)} indicator(s) found:")
            for ind in indicators:
                st.write(f"• {ind}")
        else:
            st.success("No phishing indicators found.")

        st.subheader("📊 Phishing Score (Weighted)")
        if score <= 1:
            st.metric(label="Score", value=score, delta="🟢 Safe")
        elif score <= 3:
            st.metric(label="Score", value=score, delta="🟡 Suspicious")
        else:
            st.metric(label="Score", value=score, delta="🔴 Phishing Risk")

        st.subheader("🌐 IP Geolocation Info")
        ip_rows = []
        for ip, info in ip_info.items():
            if info:
                ip_rows.append({
                    "IP": ip,
                    "Country": info.get("country", "N/A"),
                    "City": info.get("city", "N/A"),
                    "Org": info.get("org", "N/A"),
                    "Latitude": info.get("latitude"),
                    "Longitude": info.get("longitude")
                })
            else:
                ip_rows.append({
                    "IP": ip,
                    "Country": "N/A",
                    "City": "N/A",
                    "Org": "N/A",
                    "Latitude": None,
                    "Longitude": None
                })

        df = pd.DataFrame(ip_rows)
        if not df.empty and all(col in df.columns for col in ["IP", "Country", "City", "Org"]):
            st.dataframe(df[["IP", "Country", "City", "Org"]])
        else:
            st.info("No valid IP geolocation data to display.")
        
        map_df = df.dropna(subset=["Latitude", "Longitude"])
        if not map_df.empty:
            st.subheader("🗺️ IP Address Map")
            st.map(map_df.rename(columns={"Latitude": "lat", "Longitude": "lon"}))
        else:
            st.info("No valid coordinates to plot.")

        # Report Download
        st.subheader("⬇️ Download Report")
        json_report = json.dumps(report, indent=2)
        st.download_button("Download JSON Report", data=json_report, file_name="phishing_report.json", mime="application/json")


if __name__ == "__main__":
    main()
