import streamlit as st
import requests
import re
from datetime import datetime

st.set_page_config(page_title="IP Scanner", page_icon="🌐")

# ---------------------------------
# Validate IPv4 format
# ---------------------------------
def validate_ip(ip):
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


# ---------------------------------
# PRIMARY LOOKUP → KeyCDN
# ---------------------------------
def lookup_keycdn(ip):
    url = f"https://tools.keycdn.com/geo.json?host={ip}"
    headers = {"User-Agent": "keycdn-tools:https://yourdashboard.com"}

    try:
        r = requests.get(url, headers=headers, timeout=4)
        data = r.json()
        if data.get("status") == "error":
            return None
        return data.get("data", {}).get("geo")
    except:
        return None


# ---------------------------------
# FAILOVER LOOKUP → IP-API.com
# ---------------------------------
def lookup_ipapi(ip):
    url = f"http://ip-api.com/json/{ip}?fields=66846719"
    try:
        r = requests.get(url, timeout=4)
        data = r.json()
        if data.get("status") == "fail":
            return None
        return {
            "ip": ip,
            "type": "IPv4",
            "rdns": data.get("reverse"),
            "continent_name": data.get("continent"),
            "country_name": data.get("country"),
            "country_code": data.get("countryCode"),
            "region_name": data.get("regionName"),
            "city": data.get("city"),
            "timezone": data.get("timezone"),
            "local_time": datetime.now().isoformat(),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "postal_code": data.get("zip"),
            "asn": data.get("as"),
            "provider": data.get("isp"),
            "organization": data.get("org"),
            "network": data.get("as"),
            "is_eu": False,
            "device_type": None,
            "user_agent": None
        }
    except:
        return None


# ---------------------------------
# Unified lookup with fallback
# ---------------------------------
def lookup_ip(ip):
    # 1️⃣ Try KeyCDN
    data = lookup_keycdn(ip)
    if data:
        return data, "KeyCDN"

    # 2️⃣ Fallback to IP-API
    data = lookup_ipapi(ip)
    if data:
        return data, "IP-API (Fallback)"

    return None, None


# ---------------------------------
# UI
# ---------------------------------
st.title("🌐 Real-Time IP Address Scanner")
st.write("Fetch **geolocation**, **ISP**, **RDNS**, **ASN**, and more — with automatic failover.")

ip = st.text_input("Enter IP Address:", "8.8.8.8")

if st.button("Scan IP"):
    if not validate_ip(ip):
        st.error("❌ Invalid IPv4 address format!")
    else:
        with st.spinner(f"Scanning IP: {ip} ..."):
            details, source = lookup_ip(ip)

        if not details:
            st.error("❌ Lookup failed — both KeyCDN and IP-API unavailable.")
        else:
            st.success(f"🔍 Lookup Successful (Source: {source})")

            st.header("📊 IP Address Information")
            st.write(f"**IP:** {details.get('ip')}")
            st.write(f"**Type:** {details.get('type')}")
            st.write(f"**RDNS:** {details.get('rdns')}")

            st.header("🌍 Location")
            st.write(f"**Continent:** {details.get('continent_name')}")
            st.write(f"**Country:** {details.get('country_name')} ({details.get('country_code')})")
            st.write(f"**Region:** {details.get('region_name')}")
            st.write(f"**City:** {details.get('city')}")
            st.write(f"**Timezone:** {details.get('timezone')}")
            st.write(f"**Local Time:** {details.get('local_time')}")
            st.write(f"**Latitude:** {details.get('latitude')}")
            st.write(f"**Longitude:** {details.get('longitude')}")
            st.write(f"**Postal Code:** {details.get('postal_code')}")

            st.header("🛰️ Network & ISP")
            st.write(f"**ASN:** {details.get('asn')}")
            st.write(f"**ISP:** {details.get('provider')}")
            st.write(f"**Organization:** {details.get('organization')}")
            st.write(f"**Network:** {details.get('network')}")

            st.header("📝 Raw JSON Response")
            st.json(details)
