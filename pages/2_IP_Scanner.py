import streamlit as st
import requests
import socket
import geoip2.database
import os

st.set_page_config(page_title="IP Scanner", page_icon="🌐")

st.title("🌐 Advanced IP Address Scanner (WhatIsMyIPAddress Style)")

# ==========================
# Load GeoIP DB
# ==========================
GEOIP_DB_PATH = st.secrets.get("GEOIP_DB", "geo/GeoLite2-City.mmdb")

def geo_lookup(ip):
    if not os.path.exists(GEOIP_DB_PATH):
        return {"error": f"GeoIP database not found at {GEOIP_DB_PATH}"}
    try:
        reader = geoip2.database.Reader(GEOIP_DB_PATH)
        rec = reader.city(ip)
        isp = reader.asn(ip) if hasattr(reader, "asn") else None

        return {
            "ip": ip,
            "country": rec.country.name,
            "country_iso": rec.country.iso_code,
            "city": rec.city.name,
            "latitude": rec.location.latitude,
            "longitude": rec.location.longitude,
            "timezone": rec.location.time_zone,
            "postal": rec.postal.code,
            "asn": isp.autonomous_system_number if isp else None,
            "asn_org": isp.autonomous_system_organization if isp else None,
        }
    except Exception as e:
        return {"error": str(e)}

# ==========================
# Reverse DNS
# ==========================
def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Not found"

# ==========================
# Get User's Public IP
# ==========================
def get_my_ip():
    try:
        return requests.get("https://api.ipify.org").text.strip()
    except:
        try:
            return requests.get("https://checkip.amazonaws.com").text.strip()
        except:
            return "Unavailable"

# ==========================
# Blacklist Check (optional)
# ==========================
ABUSE_KEY = st.secrets.get("ABUSEIPDB_KEY", "")

def abuseipdb_check(ip):
    if not ABUSE_KEY:
        return {"skipped": True, "reason": "Missing ABUSEIPDB_KEY"}
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": 60}
        headers = {"Key": ABUSE_KEY, "Accept": "application/json"}

        r = requests.get(url, params=params, headers=headers, timeout=10)
        data = r.json()

        if "data" in data:
            return {
                "is_blacklisted": data["data"]["abuseConfidenceScore"] > 0,
                "score": data["data"]["abuseConfidenceScore"],
                "details": data["data"]
            }
        return data
    except Exception as e:
        return {"error": str(e)}

# ==========================
# INPUT SECTION
# ==========================
st.subheader("🔍 Enter an IP address or use your own")

col1, col2 = st.columns([2,1])

with col1:
    ip_input = st.text_input("Enter IP address", "")

with col2:
    if st.button("Use My IP"):
        ip_input = get_my_ip()
        st.success(f"Your IP: {ip_input}")

if not ip_input:
    st.stop()

# ==========================
# SCAN BUTTON
# ==========================
if st.button("Scan IP"):
    with st.spinner(f"Scanning {ip_input}..."):
        geo = geo_lookup(ip_input)
        dns = reverse_dns(ip_input)
        abuse = abuseipdb_check(ip_input)

    # ==========================
    # OUTPUT SECTION
    # ==========================

    st.subheader("📊 IP Address Information")

    colA, colB = st.columns(2)

    with colA:
        st.markdown("### 🌍 Location")
        st.write(f"**Country:** {geo.get('country')}")
        st.write(f"**City:** {geo.get('city')}")
        st.write(f"**Latitude:** {geo.get('latitude')}")
        st.write(f"**Longitude:** {geo.get('longitude')}")
        st.write(f"**Timezone:** {geo.get('timezone')}")
        st.write(f"**Postal Code:** {geo.get('postal')}")

    with colB:
        st.markdown("### 🛰️ Network Info")
        st.write(f"**ASN:** {geo.get('asn')}")
        st.write(f"**ISP / Org:** {geo.get('asn_org')}")
        st.write(f"**Reverse DNS:** {dns}")

    st.markdown("---")
    st.subheader("🛑 Blacklist & Reputation")

    if "skipped" in abuse:
        st.info("Blacklist check skipped — set your ABUSEIPDB_KEY in secrets.toml")
    elif "error" in abuse:
        st.error(f"Blacklist lookup failed: {abuse['error']}")
    else:
        score = abuse.get("score", 0)
        st.metric("Abuse Confidence Score", score)

        if score > 50:
            st.error("⚠️ This IP is likely malicious!")
        elif score > 0:
            st.warning("⚠️ This IP has some reported abuse.")
        else:
            st.success("✔️ No known abuse reports found.")

    st.markdown("---")

    st.json({
        "Geo Data": geo,
        "Reverse DNS": dns,
        "AbuseIPDB": abuse
    })
