import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import socket

st.set_page_config(page_title="Admin Panel", layout="wide", page_icon="🔒")

# --- SIMPLE PASSWORD PROTECTION ---
# In a real app, use st.secrets. For now, hardcoded.
ADMIN_PASSWORD = "admin" 

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.title("🔒 Admin Login")
    pwd = st.text_input("Enter Password", type="password")
    if st.button("Login"):
        if pwd == ADMIN_PASSWORD:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Wrong password")
    st.stop() # Stop here if not logged in

# --- ADMIN DASHBOARD CONTENT ---

st.title("👮‍♂️ Admin Dashboard")
st.markdown("Monitor who is accessing the application.")

LOG_FILE = "visitor_logs.csv"

try:
    df = pd.read_csv(LOG_FILE)
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
except FileNotFoundError:
    st.warning("No logs found yet. Visit the main page to generate logs.")
    st.stop()

# --- 1. ONLINE USERS CALCULATION ---
# We assume "Online" means they visited in the last 15 minutes
now = datetime.now()
active_threshold = now - timedelta(minutes=15)
active_users = df[df['Timestamp'] >= active_threshold]
online_count = active_users['IP_Address'].nunique()

# KPI CARDS
k1, k2, k3 = st.columns(3)
k1.metric("Live Users (Last 15m)", online_count)
k2.metric("Total Visits (All Time)", len(df))
k3.metric("Unique Visitors (All Time)", df['IP_Address'].nunique())

st.divider()

# --- 2. TRAFFIC OVER TIME ---
st.subheader("📈 Traffic Trends")
df['Date'] = df['Timestamp'].dt.date
daily_counts = df.groupby('Date').size().reset_index(name='Visits')
fig_traffic = px.bar(daily_counts, x='Date', y='Visits', title="Daily User Visits")
st.plotly_chart(fig_traffic, use_container_width=True)

# --- 3. USER DETAILS ---
st.subheader("🕵️ Recent Visitors")

# Function to try and resolve Hostname from IP (Optional - Can be slow)
def get_hostname(ip):
    try:
        # This performs a reverse DNS lookup
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown Host"

# Show raw data
st.dataframe(df.sort_values("Timestamp", ascending=False), use_container_width=True)

# --- 4. ADVANCED: RESOLVE HOSTNAMES ---
with st.expander("🔍 Resolve Hostnames for Active Users"):
    st.warning("This performs a Network DNS lookup. It might be slow.")
    if st.button("Resolve Hostnames"):
        active_copy = active_users.copy()
        # Apply the hostname lookup
        active_copy['Hostname'] = active_copy['IP_Address'].apply(get_hostname)
        st.dataframe(active_copy[['Timestamp', 'IP_Address', 'Hostname']])