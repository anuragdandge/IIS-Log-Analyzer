# tracker.py
import streamlit as st
import pandas as pd
from datetime import datetime
import os
# from streamlit.web.server.websocket_headers import _get_websocket_headers

LOG_FILE = "visitor_logs.csv"

def get_remote_ip():
    """
    Attempts to get the client's IP address from request headers.
    """
    try:
        headers = st.context.headers
        if headers is None:
            return "Unknown"
        
        # X-Forwarded-For is used if behind a proxy/load balancer (common in cloud)
        # Remote-Addr is the direct connection
        ip = headers.get("X-Forwarded-For")
        if not ip:
            ip = headers.get("Remote-Addr")
        return ip
    except Exception:
        return "Unknown"

def track_user():
    """
    Logs the user visit to a CSV file.
    """
    # Use session state to ensure we only log once per session (not every interaction)
    if "has_logged" not in st.session_state:
        ip_address = get_remote_ip()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create a dataframe for the new record
        new_data = pd.DataFrame([{
            "Timestamp": timestamp,
            "IP_Address": ip_address,
            "Page": "Home" # You can change this if you have multiple pages
        }])

        # Append to CSV
        if not os.path.isfile(LOG_FILE):
            new_data.to_csv(LOG_FILE, index=False)
        else:
            new_data.to_csv(LOG_FILE, mode='a', header=False, index=False)

        st.session_state.has_logged = True