# pages/2_IP_Scanner.py
import streamlit as st
import requests
import pandas as pd
import re  # <-- Import regex for validation

# This is the (undocumented but common) way to get the user's IP from Streamlit
try:
    from streamlit.runtime.scriptrunner import get_script_run_ctx
except ImportError:
    # Fallback for older Streamlit versions
    try:
        from streamlit.scriptrunner.script_run_context import get_script_run_ctx
    except ImportError:
        get_script_run_ctx = None

def validate_ip(ip):
    """Validate IP address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

@st.cache_data(ttl=3600) # Cache for 1 hour
def get_user_ip():
    """Get the user's public IP address as seen by the Streamlit server."""
    client_ip = None
    try:
        # --- NEW: Try external APIs first, as they are more reliable ---
        try:
            client_ip = requests.get("https://api.ipify.org", timeout=5).text
        except Exception:
            # Fallback to a different service if ipify fails
            try:
                response = requests.get("http://ip-api.com/json/?fields=query", timeout=5).json()
                client_ip = response.get('query')
            except Exception:
                pass # Both external APIs failed

        # --- Try the context method as a last resort ---
        if client_ip is None and get_script_run_ctx:
            ctx = get_script_run_ctx()
            if ctx and ctx.session_info:
                client_ip = ctx.session_info.client_ip
            
    except Exception:
        client_ip = None
            
    return client_ip

@st.cache_data(ttl=600) # Cache API requests for 10 minutes
def fetch_ip_details(ip_address):
    """Fetch real IP details from a public API."""
    fields = "status,message,country,regionName,city,zip,lat,lon,isp,org,as,query"
    url = f"http://ip-api.com/json/{ip_address}?fields={fields}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status() # Raise an error for bad responses
        data = response.json()
        return data
    except requests.RequestException as e:
        return {"status": "fail", "message": f"API request failed: {e}"}

def display_ip_details(data):
    """Render the IP details in a nice format."""
    if not data or data.get("status") == "fail":
        # Check for the API's specific "invalid query" message
        if data.get("message") == "invalid query":
            st.error(f"Could not retrieve details. The API reported 'invalid query'. Please ensure '{data.get('query')}' is a valid public IP address.")
        else:
            st.error(f"Could not retrieve details. Message: {data.get('message', 'Unknown error')}")
        return

    st.subheader(f"Scan Results for: {data.get('query')}")

    col1, col2 = st.columns(2)
    
    # Geolocation
    col1.metric("Location", f"{data.get('city', 'N/A')}, {data.get('regionName', 'N/A')}")
    col1.metric("Country", data.get('country', 'N/A'))
    
    # Network
    col2.metric("ISP (Internet Service Provider)", data.get('isp', 'N/A'))
    col2.metric("Organization", data.get('org', 'N/A'))
    
    # Map
    if data.get('lat') and data.get('lon'):
        map_data = pd.DataFrame({'lat': [data.get('lat')], 'lon': [data.get('lon')]})
        st.map(map_data, zoom=8)
    
    # Raw Data
    with st.expander("Show Raw API Data"):
        st.json(data)

# --- Page UI ---
st.title("🌐 Real IP Address Scanner")
st.write("Get geolocation and ISP details for your IP or any other IP address.")
st.divider()

# --- Section 1: User's Own IP ---
st.header("Your Public IP Address")
user_ip = get_user_ip()

if user_ip:
    st.info(f"Your public IP address (as seen by this server) is: **{user_ip}**")
    
    if st.button("Show My IP Details"):
        with st.spinner(f"Scanning {user_ip}..."):
            details = fetch_ip_details(user_ip)
            display_ip_details(details)
else:
    # This error message will now only show if all 3 methods fail
    st.error("Could not automatically determine your IP address. This may be due to a server network issue.")

st.divider()

# --- Section 2: Scan Another IP ---
st.header("Scan a Specific IP")
ip_to_scan = st.text_input("Enter IP Address to scan:", placeholder="e.g., 8.8.8.8 or 1.1.1.1")

if st.button("Scan IP Address"):
    # --- THIS IS THE FIX for "invalid query" ---
    if not ip_to_scan:
        st.warning("Please enter an IP address to scan.")
    elif not validate_ip(ip_to_scan):
        st.error(f"Invalid IP address format: '{ip_to_scan}'. Please enter a valid IPv4 address (e.g., 8.8.8.8).")
    else:
        # Only run if the input is not empty and is valid
        with st.spinner(f"Scanning {ip_to_scan}..."):
            details = fetch_ip_details(ip_to_scan)
            display_ip_details(details)
