import streamlit as st
import requests
from datetime import datetime

def keycdn_lookup(ip):
    url = f"https://tools.keycdn.com/geo.json?host={ip}"
    headers = {"User-Agent": "keycdn-tools:https://yourdomain.com"}

    try:
        response = requests.get(url, headers=headers, timeout=5).json()

        if "data" not in response or "geo" not in response["data"]:
            return None

        return response["data"]["geo"]

    except Exception as e:
        return {"error": str(e)}

st.title("🌐 Real-Time IP Address Scanner (Powered by KeyCDN Geo API)")
st.markdown("Enter any IPv4/IPv6 address to get detailed IP information.")

ip = st.text_input("Enter IP Address:", "8.8.8.8")

if st.button("Scan IP"):
    with st.spinner(f"Fetching details for {ip}..."):
        data = keycdn_lookup(ip)

        if not data or "error" in data:
            st.error("Failed to fetch IP details. Please try again.")
            st.json(data)
        else:
            st.success("Lookup Successful!")

            st.header("📊 IP Address Information")

            st.write(f"**IP:** {data.get('ip')}")
            st.write(f"**RDNS:** {data.get('rdns')}")
            st.write(f"**ASN:** {data.get('asn')}")
            st.write(f"**ISP:** {data.get('provider')}")

            st.header("🌍 Location")
            st.write(f"**Continent:** {data.get('continent_name')}")
            st.write(f"**Country:** {data.get('country_name')} ({data.get('country_code')})")
            st.write(f"**Region:** {data.get('region_name')}")
            st.write(f"**City:** {data.get('city')}")
            st.write(f"**Postal Code:** {data.get('postal_code')}")
            st.write(f"**Timezone:** {data.get('timezone')}")
            st.write(f"**Latitude:** {data.get('latitude')}")
            st.write(f"**Longitude:** {data.get('longitude')}")

            st.header("🛰️ Network Info")
            st.write(f"**Network:** {data.get('network')}")
            st.write(f"**Organization:** {data.get('organization')}")
            st.write(f"**Is EU?** {data.get('is_eu')}")

            st.header("🛡️ Device Information")
            st.write(f"**Device Type:** {data.get('device_type')}")
            st.write(f"**User Agent:** {data.get('user_agent')}")

            st.header("📝 Raw JSON Response")
            st.json(data)
