# pages/2_IP_Scanner.py
import streamlit as st
import requests
import pandas as pd

# This is the (undocumented but common) way to get the user's IP from Streamlit
try:
    from streamlit.runtime.scriptrunner import get_script_run_ctx
except ImportError:
    # Fallback for older Streamlit versions
    try:
        from streamlit.scriptrunner.script_run_context import get_script_run_ctx
    except ImportError:
        get_script_run_ctx = None

@st.cache_data(ttl=3600) # Cache for 1 hour
def get_user_ip():
    """Get the user's public IP address as seen by the Streamlit server."""
    client_ip = None
    try:
        if get_script_run_ctx:
            ctx = get_script_run_ctx()
            # --- THIS IS THE FIX ---
            # We must check if ctx AND ctx.session_info exist
            if ctx and ctx.session_info:
                client_ip = ctx.session_info.client_ip
        
        # Fallback if the context method fails or returns None
        if client_ip is None:
            # This will get the client IP if deployed on Streamlit Cloud,
            # or the server IP if running locally.
            client_ip = requests.get("https://api.ipify.org", timeout=5).text
            
    except Exception:
        # Final fallback
        client_ip = None
            
    return client_ip

@st.cache_data(ttl=600) # Cache API requests for 10 minutes
def fetch_ip_details(ip_address):
    """Fetch real IP details from a public API."""
    # We use ip-api.com, which is free and requires no key
    # We request specific fields to get a clean response
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
    st.error("Could not automatically determine your IP address.")

st.divider()

# --- Section 2: Scan Another IP ---
st.header("Scan a Specific IP")
ip_to_scan = st.text_input("Enter IP Address to scan:", placeholder="e.g., 8.8.8.8 or 1.1.1.1")

if st.button("Scan IP Address"):
    if ip_to_scan:
        with st.spinner(f"Scanning {ip_to_scan}..."):
            details = fetch_ip_details(ip_to_scan)
            display_ip_details(details)
    else:
        st.warning("Please enter an IP address to scan.")
