# import streamlit as st
# import pandas as pd
# import plotly.express as px
# import plotly.graph_objects as go
# import re
# from datetime import datetime

# # --- Page Configuration ---
# st.set_page_config(page_title="Magic XPI Server Log Analyzer", layout="wide")

# st.title("📊 Magic XPI Server Log Analyzer")
# st.markdown("Analyze server requests, startup durations, and uptimes.")

# # --- 1. Data Parsing Logic ---
# def parse_log_data(log_text):
#     """
#     Parses the raw log text into a Pandas DataFrame.
#     """
#     data = []
#     # Regex to capture: Time, Date, Project, Message
#     log_pattern = re.compile(r'^(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d{2}/\d{2}/\d{4})\s+(\S+)\s+(.*)$')
    
#     lines = log_text.strip().split('\n')
    
#     for line in lines:
#         match = log_pattern.match(line.strip())
#         if match:
#             time_str, date_str, project, message = match.groups()
            
#             # Combine Date and Time
#             dt_object = datetime.strptime(f"{date_str} {time_str}", "%d/%m/%Y %H:%M:%S.%f")
            
#             # Identify Event Type
#             event_type = "INFO"
#             if "request to run new server" in message:
#                 event_type = "REQUEST"
#             elif "Server was started" in message:
#                 event_type = "STARTED"
#             elif "Server was shutdown" in message:
#                 event_type = "SHUTDOWN"
            
#             # Extract Instance/Server ID (for linking Request to Start)
#             instance_id = None
#             # Look for serverId=XX in requests
#             req_id_match = re.search(r'serverId=(\d+)', message)
#             if req_id_match:
#                 instance_id = req_id_match.group(1)
            
#             # Look for Instance number XX in start logs
#             start_id_match = re.search(r'Instance number\s+(\d+)', message)
#             if start_id_match:
#                 instance_id = start_id_match.group(1)

#             # Extract Process ID (for linking Start to Shutdown)
#             pid = None
#             pid_match = re.search(r'Process Id\s*=(\d+)', message)
#             if pid_match:
#                 pid = pid_match.group(1)

#             data.append({
#                 'Timestamp': dt_object,
#                 'Project': project,
#                 'Event': event_type,
#                 'InstanceID': instance_id,
#                 'PID': pid,
#                 'Message': message
#             })
            
#     return pd.DataFrame(data)

# def process_sessions(df):
#     """
#     Logic to calculate durations:
#     1. Startup Time: Time between REQUEST and STARTED (Linked by InstanceID)
#     2. Uptime: Time between STARTED and SHUTDOWN (Linked by PID)
#     """
#     sessions = []
    
#     projects = df['Project'].unique()
    
#     for project in projects:
#         proj_df = df[df['Project'] == project].sort_values('Timestamp')
        
#         # 1. Analyze Startup Delays
#         requests = proj_df[proj_df['Event'] == 'REQUEST']
#         starts = proj_df[proj_df['Event'] == 'STARTED']
        
#         # Merge on InstanceID to find startup time
#         if not requests.empty and not starts.empty:
#             merged_startups = pd.merge(requests, starts, on='InstanceID', suffixes=('_req', '_start'))
#             merged_startups['Startup_Duration_Sec'] = (merged_startups['Timestamp_start'] - merged_startups['Timestamp_req']).dt.total_seconds()
            
#             for _, row in merged_startups.iterrows():
#                 sessions.append({
#                     'Project': project,
#                     'Type': 'Startup Phase',
#                     'Start_Time': row['Timestamp_req'],
#                     'End_Time': row['Timestamp_start'],
#                     'Duration_Sec': row['Startup_Duration_Sec'],
#                     'ID': row['InstanceID'],
#                     'Status': 'Success'
#                 })

#         # 2. Analyze Runtime/Uptime
#         shutdowns = proj_df[proj_df['Event'] == 'SHUTDOWN']
        
#         # Merge on PID to find uptime
#         if not starts.empty and not shutdowns.empty:
#             merged_uptime = pd.merge(starts, shutdowns, on='PID', suffixes=('_start', '_end'))
#             merged_uptime['Uptime_Duration_Sec'] = (merged_uptime['Timestamp_end'] - merged_uptime['Timestamp_start']).dt.total_seconds()
            
#             for _, row in merged_uptime.iterrows():
#                 sessions.append({
#                     'Project': project,
#                     'Type': 'Server Running',
#                     'Start_Time': row['Timestamp_start'],
#                     'End_Time': row['Timestamp_end'],
#                     'Duration_Sec': row['Uptime_Duration_Sec'],
#                     'ID': row['PID'],
#                     'Status': 'Finished'
#                 })
                
#     return pd.DataFrame(sessions)

# # --- 2. Input Section ---
# with st.sidebar:
#     st.header("1. Input Data")
#     default_log = """14:00:50.147  07/10/2025                                              Project1                         request to run new server, params:  project=C:\Magicxpi4141\Runtime\projects\Project1\Project1\Project1.ibp, SpaceName=-[MAGICXPI_GS]LookupGroupName=  -[MAGICXPI_GS]LookupLocators= group=-[MAGICXPI_GS]LookupLocators= serverId=5 locators=
#  14:01:13.094  07/10/2025                                              Project1                         Server was started.  -  Instance number 5 ,The server was started with a non-production license, and will shut down in 24  hours. Process Id =5440
#  14:09:56.798  07/10/2025                                              Project1                         Server was shutdown. Process Id =5440
#  12:19:31.258  17/10/2025                                              FTP_TEST                         request to run new server, params:  project=C:\Magicxpi4141\Runtime\projects\FTP_TEST\FTP_TEST\FTP_TEST.ibp, SpaceName=-[MAGICXPI_GS]LookupGroupName=  -[MAGICXPI_GS]LookupLocators= group=-[MAGICXPI_GS]LookupLocators= serverId=17 locators=
#  12:19:45.144  17/10/2025                                              FTP_TEST                         Server was started.  -  Instance number 17 ,The server was started with a non-production license, and will shut down in 24  hours. Process Id =2888
#  12:20:52.157  17/10/2025                                              FTP_TEST                         Server was shutdown. Process Id =2888
#  12:23:14.550  29/10/2025                                              Genysoft_POC                     request to run new server, params:  project=C:\Magicxpi4141\Runtime\projects\Genysoft_POC\Genysoft_POC\Genysoft_POC.ibp, SpaceName=-[MAGICXPI_GS]LookupGroupName=  -[MAGICXPI_GS]LookupLocators= group=-[MAGICXPI_GS]LookupLocators= serverId=29 locators=
#  12:23:31.270  29/10/2025                                              Genysoft_POC                     Server was started.  -  Instance number 29 ,The server was started with a non-production license, and will shut down in 24  hours. Process Id =10184
#  14:07:52.234  29/10/2025                                              Genysoft_POC                     Server was shutdown. Process Id =10184"""
    
#     log_input = st.text_area("Paste Log Data Here", value=default_log, height=300)
#     process_btn = st.button("Analyze Logs")

# # --- 3. Main Analysis ---
# if process_btn or log_input:
#     # A. Parse Raw Data
#     df_raw = parse_log_data(log_input)
    
#     if df_raw.empty:
#         st.error("No valid log lines found. Please check format.")
#     else:
#         # B. Calculate Sessions (Durations)
#         df_sessions = process_sessions(df_raw)
        
#         # --- Top Level Metrics ---
#         st.subheader("🚀 High-Level Insights")
#         c1, c2, c3, c4 = st.columns(4)
        
#         total_requests = len(df_raw[df_raw['Event'] == 'REQUEST'])
        
#         # Filter for logic
#         startup_df = df_sessions[df_sessions['Type'] == 'Startup Phase']
#         uptime_df = df_sessions[df_sessions['Type'] == 'Server Running']
        
#         avg_startup = startup_df['Duration_Sec'].mean() if not startup_df.empty else 0
#         total_runtime = uptime_df['Duration_Sec'].sum() / 60 if not uptime_df.empty else 0 # in mins
        
#         with c1: st.metric("Total Projects Requested", total_requests)
#         with c2: st.metric("Avg Startup Time (sec)", f"{avg_startup:.2f}s")
#         with c3: st.metric("Total Server Runtime (min)", f"{total_runtime:.1f}m")
#         with c4: st.metric("Unique Projects", df_raw['Project'].nunique())

#         st.divider()

#         # --- Visualizations ---
        
#         # 1. TIMELINE (GANTT CHART)
#         st.subheader("📅 Project Execution Timeline")
#         if not df_sessions.empty:
#             fig_gantt = px.timeline(
#                 df_sessions, 
#                 x_start="Start_Time", 
#                 x_end="End_Time", 
#                 y="Project", 
#                 color="Type",
#                 hover_data=['Duration_Sec', 'ID'],
#                 title="Startup Phase vs Server Running Time",
#                 color_discrete_map={"Startup Phase": "#FFA15A", "Server Running": "#636EFA"}
#             )
#             fig_gantt.update_yaxes(autorange="reversed") # Projects listed top to bottom
#             st.plotly_chart(fig_gantt, use_container_width=True)
#         else:
#             st.info("Not enough data pairs to generate timeline.")

#         c_left, c_right = st.columns(2)

#         # 2. STARTUP DURATION BAR CHART
#         with c_left:
#             st.subheader("⏱️ Time Taken to Start Server")
#             if not startup_df.empty:
#                 fig_bar = px.bar(
#                     startup_df, 
#                     x='Project', 
#                     y='Duration_Sec',
#                     color='Project',
#                     text_auto='.2f',
#                     title="Startup Latency (Request → Started)",
#                     labels={'Duration_Sec': 'Seconds'}
#                 )
#                 st.plotly_chart(fig_bar, use_container_width=True)
#             else:
#                 st.warning("No startup phases detected.")

#         # 3. REQUEST VS FAILURE/SHUTDOWN ANALYSIS
#         with c_right:
#             st.subheader("📉 Request vs Shutdown Count")
#             # Count events per project
#             event_counts = df_raw[df_raw['Event'].isin(['REQUEST', 'SHUTDOWN'])].groupby(['Project', 'Event']).size().reset_index(name='Count')
            
#             fig_status = px.bar(
#                 event_counts, 
#                 x='Project', 
#                 y='Count', 
#                 color='Event',
#                 barmode='group',
#                 title="Did every request have a clean shutdown?",
#                 color_discrete_map={"REQUEST": "green", "SHUTDOWN": "red"}
#             )
#             st.plotly_chart(fig_status, use_container_width=True)

#         # --- Detailed Data View ---
#         st.divider()
#         with st.expander("🔎 View Parsed Raw Data"):
#             st.dataframe(df_raw)
        
#         with st.expander("🔎 View Calculated Sessions Data"):
#             st.dataframe(df_sessions)
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import re
from datetime import datetime
import io

# --- Page Configuration ---
st.set_page_config(page_title="Magic XPI Log Analyzer", layout="wide", page_icon="📂")

st.title("📂 Magic XPI Server Log Analyzer")
st.markdown("""
Upload your Magic XPI Server log file to visualize:
* **Startup Delays:** How long projects take to initialize.
* **Timeline:** When projects ran and for how long.
* **Health:** Detect successful startups vs. errors.
""")

# --- 1. Data Parsing Logic ---
@st.cache_data
def parse_log_data(log_content):
    """
    Parses the raw string content into a Pandas DataFrame.
    """
    data = []
    # Regex to capture: Time, Date, Project, Message
    # Looks for: HH:MM:SS.mmm  DD/MM/YYYY   ProjectName   Rest of message
    log_pattern = re.compile(r'^(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d{2}/\d{2}/\d{4})\s+(\S+)\s+(.*)$')
    
    lines = log_content.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line: continue
        
        match = log_pattern.match(line)
        if match:
            time_str, date_str, project, message = match.groups()
            
            try:
                dt_object = datetime.strptime(f"{date_str} {time_str}", "%d/%m/%Y %H:%M:%S.%f")
            except ValueError:
                continue # Skip if date format is weird

            # --- Identify Event Type ---
            event_type = "INFO"
            if "request to run new server" in message:
                event_type = "REQUEST"
            elif "Server was started" in message:
                event_type = "STARTED"
            elif "Server was shutdown" in message:
                event_type = "SHUTDOWN"
            
            # --- Identify Potential Failures ---
            # Check for error keywords in the message
            is_error = False
            error_reason = None
            if any(x in message.lower() for x in ['error', 'exception', 'failed', 'could not start', 'license expired']):
                event_type = "ERROR"
                is_error = True
                error_reason = message[:100] + "..." # Take first 100 chars as reason

            # --- Extract IDs for Linking ---
            instance_id = None
            # Extract serverId=5 or Instance number 5
            id_match = re.search(r'(?:serverId=|Instance number\s+)(\d+)', message)
            if id_match:
                instance_id = id_match.group(1)

            # Extract Process Id
            pid = None
            pid_match = re.search(r'Process Id\s*=\s*(\d+)', message)
            if pid_match:
                pid = pid_match.group(1)

            data.append({
                'Timestamp': dt_object,
                'Project': project,
                'Event': event_type,
                'InstanceID': instance_id,
                'PID': pid,
                'Message': message,
                'Is_Error': is_error,
                'Error_Reason': error_reason
            })
            
    return pd.DataFrame(data)

def process_sessions(df):
    """
    Calculates durations for startup and uptime.
    """
    sessions = []
    projects = df['Project'].unique()
    
    for project in projects:
        proj_df = df[df['Project'] == project].sort_values('Timestamp')
        
        # 1. Analyze Startup Latency (Request -> Started)
        requests = proj_df[proj_df['Event'] == 'REQUEST']
        starts = proj_df[proj_df['Event'] == 'STARTED']
        
        if not requests.empty and not starts.empty:
            # Merge based on InstanceID (if available) or assume chronological order
            merged_startups = pd.merge(requests, starts, on='InstanceID', suffixes=('_req', '_start'), how='inner')
            merged_startups['Startup_Duration_Sec'] = (merged_startups['Timestamp_start'] - merged_startups['Timestamp_req']).dt.total_seconds()
            
            for _, row in merged_startups.iterrows():
                sessions.append({
                    'Project': project,
                    'Type': 'Startup Phase',
                    'Start_Time': row['Timestamp_req'],
                    'End_Time': row['Timestamp_start'],
                    'Duration_Sec': row['Startup_Duration_Sec'],
                    'Details': f"Instance {row['InstanceID']}"
                })

        # 2. Analyze Runtime (Started -> Shutdown)
        shutdowns = proj_df[proj_df['Event'] == 'SHUTDOWN']
        
        if not starts.empty and not shutdowns.empty:
            merged_uptime = pd.merge(starts, shutdowns, on='PID', suffixes=('_start', '_end'), how='inner')
            merged_uptime['Uptime_Duration_Sec'] = (merged_uptime['Timestamp_end'] - merged_uptime['Timestamp_start']).dt.total_seconds()
            
            for _, row in merged_uptime.iterrows():
                sessions.append({
                    'Project': project,
                    'Type': 'Server Running',
                    'Start_Time': row['Timestamp_start'],
                    'End_Time': row['Timestamp_end'],
                    'Duration_Sec': row['Uptime_Duration_Sec'],
                    'Details': f"PID {row['PID']}"
                })
                
    return pd.DataFrame(sessions)

# --- 2. File Upload Section ---
st.sidebar.header("1. Upload Data")
uploaded_file = st.sidebar.file_uploader("Upload Log File (.log, .txt)", type=['log', 'txt'])

# Optional: Load sample data if no file is uploaded
use_sample = st.sidebar.checkbox("Use Sample Data (Demo)")

log_text = ""

if uploaded_file is not None:
    # Read file content and decode bytes to string
    try:
        log_text = uploaded_file.getvalue().decode("utf-8")
    except UnicodeDecodeError:
        st.error("Error decoding file. Please ensure it is a UTF-8 text file.")
elif use_sample:
    # Your sample data
    log_text = """14:00:50.147  07/10/2025  Project1  request to run new server, params: serverId=5
 14:01:13.094  07/10/2025  Project1  Server was started. - Instance number 5. Process Id =5440
 14:09:56.798  07/10/2025  Project1  Server was shutdown. Process Id =5440
 12:19:31.258  17/10/2025  FTP_TEST  request to run new server, params: serverId=17
 12:19:45.144  17/10/2025  FTP_TEST  Server was started. - Instance number 17. Process Id =2888
 12:20:52.157  17/10/2025  FTP_TEST  Server was shutdown. Process Id =2888
 12:23:14.550  29/10/2025  Genysoft_POC request to run new server, params: serverId=29
 12:23:31.270  29/10/2025  Genysoft_POC Server was started. - Instance number 29. Process Id =10184
 14:07:52.234  29/10/2025  Genysoft_POC Server was shutdown. Process Id =10184
 15:00:00.000  30/10/2025  Err_Project  request to run new server, params: serverId=99
 15:00:05.000  30/10/2025  Err_Project  CRITICAL ERROR: License expired, failed to start."""

# --- 3. Main Analysis ---
if log_text:
    df_raw = parse_log_data(log_text)
    
    if df_raw.empty:
        st.warning("Parsed 0 lines. Please check the log file format matches: 'HH:MM:SS.mmm DD/MM/YYYY ProjectName Message'")
    else:
        df_sessions = process_sessions(df_raw)

        # --- Metrics Row ---
        st.subheader("🚀 Overview")
        m1, m2, m3, m4 = st.columns(4)
        
        req_count = len(df_raw[df_raw['Event'] == 'REQUEST'])
        error_count = len(df_raw[df_raw['Is_Error'] == True])
        
        # Calculate averages
        avg_startup = 0
        if not df_sessions.empty:
            startups = df_sessions[df_sessions['Type'] == 'Startup Phase']
            if not startups.empty:
                avg_startup = startups['Duration_Sec'].mean()
        
        with m1: st.metric("Total Requests", req_count)
        with m2: st.metric("Errors / Failures", error_count, delta_color="inverse")
        with m3: st.metric("Avg Startup Time", f"{avg_startup:.2f}s")
        with m4: st.metric("Projects", df_raw['Project'].nunique())

        st.divider()

        # --- Tabbed Visualization ---
        tab1, tab2, tab3 = st.tabs(["⏳ Timeline & Performance", "❌ Failure Analysis", "📋 Data Explorer"])

        with tab1:
            st.subheader("Project Starting Time & Duration")
            
            if not df_sessions.empty:
                # GANTT CHART
                fig_timeline = px.timeline(
                    df_sessions,
                    x_start="Start_Time",
                    x_end="End_Time",
                    y="Project",
                    color="Type",
                    hover_data=['Duration_Sec', 'Details'],
                    color_discrete_map={"Startup Phase": "#FFA15A", "Server Running": "#636EFA"},
                    title="Gantt Chart: Startup (Orange) vs Running (Blue)"
                )
                fig_timeline.update_yaxes(autorange="reversed")
                st.plotly_chart(fig_timeline, use_container_width=True)

                # STARTUP LATENCY BAR CHART
                startup_only = df_sessions[df_sessions['Type'] == 'Startup Phase']
                if not startup_only.empty:
                    fig_lat = px.bar(
                        startup_only,
                        x="Project",
                        y="Duration_Sec",
                        color="Duration_Sec",
                        color_continuous_scale="RdYlGn_r", # Red is slow, Green is fast
                        title="How long does it take to start? (Seconds)",
                        labels={"Duration_Sec": "Seconds"}
                    )
                    st.plotly_chart(fig_lat, use_container_width=True)
            else:
                st.info("Insufficient data to generate timeline (Need pairs of Request+Start or Start+Shutdown).")

        with tab2:
            st.subheader("Reasons for Failure")
            
            # Filter specifically for errors
            errors_df = df_raw[df_raw['Is_Error'] == True]
            
            if not errors_df.empty:
                col_a, col_b = st.columns([1, 2])
                
                with col_a:
                    # Pie chart of affected projects
                    fig_pie = px.pie(errors_df, names='Project', title="Errors by Project")
                    st.plotly_chart(fig_pie, use_container_width=True)
                
                with col_b:
                    st.markdown("#### Detailed Error Logs")
                    st.dataframe(errors_df[['Timestamp', 'Project', 'Error_Reason', 'Message']], hide_index=True)
            else:
                st.success("🎉 No explicit failures detected in the uploaded logs!")
            
            # Request vs Start vs Shutdown Counts
            st.subheader("Process Lifecycle Counts")
            lifecycle_counts = df_raw.groupby(['Project', 'Event']).size().reset_index(name='Count')
            fig_life = px.bar(
                lifecycle_counts, 
                x='Project', y='Count', color='Event', 
                barmode='group',
                title="Did every Request result in a Start and Shutdown?",
                color_discrete_map={"REQUEST": "blue", "STARTED": "green", "SHUTDOWN": "gray", "ERROR": "red"}
            )
            st.plotly_chart(fig_life, use_container_width=True)

        with tab3:
            st.subheader("Raw Log Data")
            st.dataframe(df_raw, use_container_width=True)
            
            st.subheader("Processed Session Data")
            st.dataframe(df_sessions, use_container_width=True)

else:
    st.info("👈 Please upload a .log or .txt file in the sidebar to begin analysis.")