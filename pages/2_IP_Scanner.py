import streamlit as st
import socket
import json
import requests
import maxminddb
import re
import asyncio
import concurrent.futures
from datetime import datetime

# ---------------------------------------------------------
# UTIL — Validate IP
# ---------------------------------------------------------
def validate_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(x) <= 255 for x in ip.split("."))


# ---------------------------------------------------------
# UTIL — Reverse DNS
# ---------------------------------------------------------
def reverse_dns_lookup(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
        return host
    except:
        return "Unknown / Not Resolved"


# ---------------------------------------------------------
# UTIL — Port Scan
# ---------------------------------------------------------
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP SSL",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP Proxy"
}

async def scan_port(ip, port):
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=0.5)
        writer.close()
        return port
    except:
        return None

async def scan_ports_async(ip):
    tasks = [scan_port(ip, port) for port in COMMON_PORTS.keys()]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]


# ---------------------------------------------------------
# UTIL — GeoIP Lookup
# ---------------------------------------------------------
def geoip_lookup(ip):
    try:
        # User-uploaded database takes priority
        if "geoip_path" in st.session_state:
            db_path = st.session_state["geoip_path"]
        else:
            db_path = "geo/GeoLite2-City.mmdb"  # Default bundled file

        reader = maxminddb.open_database(db_path)
        record = reader.get(ip)
        reader.close()

        if not record:
            return None

        return {
            "country": record.get("country", {}).get("names", {}).get("en", "Unknown"),
            "city": record.get("city", {}).get("names", {}).get("en", "Unknown"),
            "latitude": record.get("location", {}).get("latitude"),
            "longitude": record.get("location", {}).get("longitude"),
            "postal": record.get("postal", {}).get("code", "N/A"),
            "timezone": record.get("location", {}).get("time_zone", "N/A")
        }

    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------
# UTIL — WHOIS / RDAP
# ---------------------------------------------------------
def rdap_lookup(ip):
    try:
        url = f"https://rdap.db.ripe.net/ip/{ip}"
        data = requests.get(url, timeout=5).json()
        return {
            "name": data.get("name", "Unknown"),
            "country": data.get("country", "Unknown"),
            "asn": data.get("handle", "Unknown"),
            "org": data.get("remarks", [{}])[0].get("description", "N/A")
        }
    except:
        return {"name": "Unknown", "country": "Unknown", "asn": "Unknown", "org": "Unknown"}


# ---------------------------------------------------------
# UTIL — AbuseIPDB
# ---------------------------------------------------------
def abuse_ipdb_lookup(ip):
    if "ABUSEIPDB_KEY" not in st.secrets:
        return None  # no key

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": st.secrets["ABUSEIPDB_KEY"], "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "180"}

        res = requests.get(url, headers=headers, params=params, timeout=5).json()
        data = res["data"]

        return {
            "abuse_score": data["abuseConfidenceScore"],
            "reports": data["totalReports"],
            "isp": data["isp"],
            "hostnames": data["hostnames"]
        }
    except:
        return None


# ---------------------------------------------------------
# UTIL — VirusTotal
# ---------------------------------------------------------
def virustotal_lookup(ip):
    if "VT_KEY" not in st.secrets:
        return None

    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": st.secrets["VT_KEY"]}

        res = requests.get(url, headers=headers, timeout=5).json()
        data = res["data"]["attributes"]

        return {
            "harmless": data["last_analysis_stats"]["harmless"],
            "malicious": data["last_analysis_stats"]["malicious"],
            "suspicious": data["last_analysis_stats"]["suspicious"],
            "undetected": data["last_analysis_stats"]["undetected"]
        }
    except:
        return None


# ---------------------------------------------------------
# STREAMLIT UI
# ---------------------------------------------------------
st.title("🌐 Advanced IP Intelligence Scanner")

st.info("This scanner performs **GeoIP*, *WHOIS/RDAP*, *Blacklist checks*, *Port scan*, *DNS*, and *Threat Intelligence lookups*.")  

ip = st.text_input("Enter IP Address:", "8.8.8.8")

uploaded_geo = st.file_uploader("Upload GeoLite2-City.mmdb (Optional)", type=["mmdb"])
if uploaded_geo:
    st.session_state["geoip_path"] = f"geoip_upload.mmdb"
    with open("geoip_upload.mmdb", "wb") as f:
        f.write(uploaded_geo.read())
    st.success("Custom GeoIP database loaded.")


if st.button("🚀 Scan IP"):
    if not validate_ip(ip):
        st.error("Invalid IP address format!")
        st.stop()

    with st.spinner("Performing full intelligence scan..."):

        # ------------------------------
        # 1. Reverse DNS
        # ------------------------------
        dns_result = reverse_dns_lookup(ip)

        # ------------------------------
        # 2. GeoIP
        # ------------------------------
        geo = geoip_lookup(ip)

        # ------------------------------
        # 3. RDAP WHOIS
        # ------------------------------
        rdap = rdap_lookup(ip)

        # ------------------------------
        # 4. Threat Intel APIs
        # ------------------------------
        abuse = abuse_ipdb_lookup(ip)
        vt = virustotal_lookup(ip)

        # ------------------------------
        # 5. Port Scan
        # ------------------------------
        open_ports = asyncio.run(scan_ports_async(ip))

    # ---------------------------------------------------------
    # REPORT OUTPUT
    # ---------------------------------------------------------

    st.subheader("📌 Basic Information")
    st.write(f"**IP Address:** {ip}")
    st.write(f"**Reverse DNS:** {dns_result}")
    st.write(f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    st.subheader("🌍 GeoIP Information")
    if "error" in geo:
        st.error(f"GeoIP Error: {geo['error']}")
    else:
        st.json(geo)

    st.subheader("🗂 RDAP / WHOIS Information")
    st.json(rdap)

    st.subheader("🛑 AbuseIPDB (Blacklist Check)")
    if abuse:
        st.json(abuse)
    else:
        st.info("No AbuseIPDB key provided — skipping.")

    st.subheader("🧪 VirusTotal Reputation")
    if vt:
        st.json(vt)
    else:
        st.info("No VirusTotal key provided — skipping.")

    st.subheader("🔌 Port Scan Result")
    if open_ports:
        table = [{"port": p, "service": COMMON_PORTS[p]} for p in open_ports]
        st.table(table)
    else:
        st.success("No common ports open.")

    st.success("Scan Complete ✔")
