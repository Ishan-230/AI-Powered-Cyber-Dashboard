import streamlit as st
import requests
import re
from datetime import datetime

st.set_page_config(page_title="IP Scanner", page_icon="🌐")


# ---------------------------
# IP Validation
# ---------------------------
def validate_ip(ip):
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(part) <= 255 for part in parts)


# ---------------------------
# KeyCDN Geo API Lookup
# ---------------------------
def keycdn_lookup(ip):
    url = f"https://tools.keycdn.com/geo.json?host={ip}"
    headers = {"User-Agent": "keycdn-tools:https://your-app.com"}

    try:
        resp = requests.get(url, headers=headers, timeout=6)
        data = resp.json()

        # Handle reserved / invalid IP responses
        if data.get("status") == "error":
            return {"error": data.get("description", "Lookup failed.")}

        geo = data.get("data", {}).get("geo", None)

        if not geo:
            return {"error": "Geo information not found."}

        return geo
    except Exception as e:
        return {"error": str(e)}


# ---------------------------
# UI
# ---------------------------
st.title("🌐 Real-Time IP Address Scanner (KeyCDN Powered)")
st.write("Enter any IPv4/IPv6 address to fetch **geolocation**, **ISP**, **ASN**, **RDNS**, and more.")


# ---------------------------
# Input
# ---------------------------
ip = st.text_input("Enter IP Address:", "8.8.8.8")

if st.button("Scan IP"):
    if not validate_ip(ip):
        st.error("❌ Invalid IP address format")
    else:
        with st.spinner(f"Scanning {ip}..."):
            info = keycdn_lookup(ip)

        if "error" in info:
            st.error(f"❌ Lookup failed — {info['error']}")
        else:
            # ---------------------------
            # SUCCESS OUTPUT
            # ---------------------------
            st.success("🔍 Lookup Successful!")

            st.header("📊 IP Address Information")
            st.write(f"**IP:** {info.get('ip')}")
            st.write(f"**Type:** {info.get('type')}")
            st.write(f"**RDNS:** {info.get('rdns')}")

            st.header("🌍 Location")
            st.write(f"**Continent:** {info.get('continent_name')}")
            st.write(f"**Country:** {info.get('country_name')} ({info.get('country_code')})")
            st.write(f"**Region:** {info.get('region_name')}")
            st.write(f"**City:** {info.get('city')}")
            st.write(f"**Timezone:** {info.get('timezone')}")
            st.write(f"**Local Time:** {info.get('local_time')}")
            st.write(f"**Latitude:** {info.get('latitude')}")
            st.write(f"**Longitude:** {info.get('longitude')}")
            st.write(f"**Postal Code:** {info.get('postal_code')}")

            st.header("🛰️ Network & ISP")
            st.write(f"**ASN:** {info.get('asn')}")
            st.write(f"**ISP / Provider:** {info.get('provider')}")
            st.write(f"**Network:** {info.get('network')}")
            st.write(f"**Organization:** {info.get('organization')}")

            st.header("🛡️ Additional Info")
            st.write(f"**Is EU:** {info.get('is_eu')}")
            st.write(f"**Device Type:** {info.get('device_type')}")
            st.write(f"**User Agent:** {info.get('user_agent')}")

            st.header("📝 Raw JSON Response")
            st.json(info)
