import streamlit as st
import requests
from datetime import datetime
import re

# ---------- Utility: Validate IP ----------
def validate_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


# ---------- API Lookup ----------
def lookup_ip(ip: str):
    """Fetch complete IP details using ipwho.is (free, no key)."""
    url = f"https://ipwho.is/{ip}"
    response = requests.get(url, timeout=5).json()
    return response


# ---------- UI ----------
st.title("🌐 Real-Time IP Address Scanner (Powered by ipwho.is)")
st.write("Enter any IPv4/IPv6 address to fetch **live geolocation, ISP, security flags, proxy/Tor detection, ASN, and more**.")

ip = st.text_input("Enter IP Address:", value="8.8.8.8")

if st.button("🔍 Scan Now"):
    if not validate_ip(ip):
        st.error("❌ Invalid IP address format!")
        st.stop()

    with st.spinner(f"Fetching real-time data for IP: {ip} ..."):
        data = lookup_ip(ip)

    if not data.get("success", False):
        st.error("❌ Lookup failed. The IP may be invalid or unreachable.")
        st.json(data)
        st.stop()

    st.success("✅ IP Lookup Successful")

    st.header("📊 IP Address Information")
    st.write(f"**IP:** {data['ip']}")
    st.write(f"**Type:** {data.get('type', 'Unknown')}")
    st.write(f"**Continent:** {data.get('continent', 'N/A')}")
    st.write(f"**Country:** {data.get('country', 'N/A')} ({data.get('country_code', '')})")
    st.write(f"**Region:** {data.get('region', 'N/A')}")
    st.write(f"**City:** {data.get('city', 'N/A')}")
    st.write(f"**Timezone:** {data.get('timezone', {}).get('id', 'N/A')}")
    st.write(f"**Local Time:** {data.get('timezone', {}).get('current_time', 'N/A')}")
    st.write(f"**Latitude:** {data.get('latitude', 'N/A')}")
    st.write(f"**Longitude:** {data.get('longitude', 'N/A')}")
    st.write(f"**Postal Code:** {data.get('postal', 'N/A')}")

    st.divider()

    # ---------- NETWORK INFO ----------
    st.header("🛰 Network Information")
    conn = data.get("connection", {})

    st.write(f"**ASN:** {conn.get('asn', 'N/A')}")
    st.write(f"**ISP:** {conn.get('isp', 'N/A')}")
    st.write(f"**Organization:** {conn.get('org', 'N/A')}")
    st.write(f"**Domain:** {conn.get('domain', 'N/A')}")

    st.divider()

    # ---------- SECURITY ----------
    st.header("🛡 Security Detection")
    sec = data.get("security", {})

    st.write("**Proxy:**", "🟢 No" if not sec.get("proxy") else "🔴 Yes")
    st.write("**VPN:**", "🟢 No" if not sec.get("vpn") else "🔴 Yes")
    st.write("**TOR:**", "🟢 No" if not sec.get("tor") else "🔴 Yes")
    st.write("**Hosting:**", "🟢 No" if not sec.get("hosting") else "⚠️ Hosting Provider")
    st.write("**Threat Level:**", sec.get("threat_level", "Unknown"))
    st.write("**Threat Types:**", sec.get("threat_types", "None"))

    st.divider()

    # ---------- MAP ----------
    st.header("🗺 Geolocation Map")
    lat = data.get("latitude")
    lon = data.get("longitude")

    if lat and lon:
        st.map({"lat": [lat], "lon": [lon]})
    else:
        st.warning("Location data unavailable — map cannot be displayed.")

    st.divider()

    # ---------- RAW DATA ----------
    with st.expander("📦 Raw API Response (Debugging)"):
        st.json(data)

    # ---------- FOOTER ----------
    st.caption("Data retrieved via https://ipwho.is — No API key required.")
