
# import streamlit as st
# import pandas as pd
# import plotly.express as px

# # Page configuration
# st.set_page_config(page_title="MagicLog Analyzer", layout="wide", page_icon="🔮")

# st.title("🔮  Log Analyzer")
# st.markdown("This dashboard focuses **exclusively** on `MgWebRequester.dll` traffic and decodes the `arguments` parameter.")

# # --- 1. PARSING FUNCTION ---
# @st.cache_data
# def parse_log_file(uploaded_file):
#     content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
#     lines = content.splitlines()

#     fields = None
#     data_lines = []

#     for line in lines:
#         line = line.strip()
#         if not line:
#             continue
#         if line.startswith("#"):
#             if line.lower().startswith("#fields:"):
#                 fields = line.split(":", 1)[1].strip().split()
#             continue
#         data_lines.append(line)

#     if fields is None:
#         return None

#     rows = []
#     for ln in data_lines:
#         parts = ln.split()
#         if len(parts) < len(fields):
#             continue
#         rows.append(dict(zip(fields, parts)))

#     df = pd.DataFrame(rows)

#     if "date" in df.columns and "time" in df.columns:
#         df["timestamp"] = pd.to_datetime(df["date"] + " " + df["time"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
#         df = df.dropna(subset=["timestamp"])
#         df = df.sort_values("timestamp")
    
#     return df

# # --- 2. FILE UPLOADER ---
# uploaded_file = st.sidebar.file_uploader("Choose a Log File", type=["log", "txt"])

# if uploaded_file is not None:
#     with st.spinner("Parsing and Filtering for Magic requests..."):
#         df_raw = parse_log_file(uploaded_file)

#     if df_raw is None:
#         st.error("Header not found. Ensure W3C format.")
#     elif df_raw.empty:
#         st.warning("No data found in file.")
#     else:
#         # --- 3. FILTER & TRANSFORM LOGIC (MAGIC SPECIFIC) ---
        
#         # Check required columns
#         if "cs-uri-stem" not in df_raw.columns or "cs-uri-query" not in df_raw.columns:
#             st.error("Log file missing 'cs-uri-stem' or 'cs-uri-query' columns.")
#             st.stop()

#         # A. Filter specifically for MgWebRequester
#         df_magic = df_raw[df_raw["cs-uri-stem"].str.contains("MgWebRequester.dll", case=False, na=False)].copy()

#         if df_magic.empty:
#             st.warning("No 'MgWebRequester.dll' requests found in this log file.")
#             st.stop()

#         # B. Extract & Decode Arguments
#         # Extract everything after 'arguments=' until the next '&' or end of string
#         df_magic['extracted_arg'] = df_magic['cs-uri-query'].str.extract(r"arguments=([^&]*)")
        
#         # Replace %23 with # and handle missing values
#         df_magic['flow_name'] = df_magic['extracted_arg'].str.replace('%23', '#', regex=False)
#         df_magic['flow_name'] = df_magic['flow_name'].fillna("No Arguments / Index")

#         # --- 4. SIDEBAR DATE FILTER (Applied to Magic Data) ---
#         st.sidebar.header("Filters")
#         min_date = df_magic["timestamp"].min()
#         max_date = df_magic["timestamp"].max()
        
#         col1, col2 = st.sidebar.columns(2)
#         start_date = col1.date_input("Start Date", min_date.date())
#         end_date = col2.date_input("End Date", max_date.date())

#         mask = (df_magic["timestamp"].dt.date >= start_date) & (df_magic["timestamp"].dt.date <= end_date)
#         df_final = df_magic.loc[mask].copy()

#         # --- 5. DASHBOARD ---

#         # KPIs
#         total_reqs = len(df_final)
#         unique_flows = df_final['flow_name'].nunique()
#         errors = df_final[df_final['sc-status'].astype(str).str.startswith(('4', '5'))]
#         error_count = len(errors)

#         k1, k2, k3 = st.columns(3)
#         k1.metric("Total Magic Requests", f"{total_reqs:,}")
#         k2.metric("Unique Flows/Arguments", f"{unique_flows:,}")
#         k3.metric("Error Responses (4xx/5xx)", f"{error_count:,}", delta_color="inverse")

#         st.divider()

#         # --- SECTION A: TOP ARGUMENTS (The Core Insight) ---
#         st.subheader("🏆 Top Magic Flows (Arguments)")
        
#         flow_counts = df_final["flow_name"].value_counts().reset_index()
#         flow_counts.columns = ["Flow Name", "Count"]
#         top_flows = flow_counts.head(15)

#         col_flow_chart, col_flow_table = st.columns([3, 1])
        
#         with col_flow_chart:
#             fig_flows = px.bar(
#                 top_flows, 
#                 x="Count", 
#                 y="Flow Name", 
#                 orientation='h', 
#                 title="Top 15 Most Executed Flows",
#                 color="Count",
#                 color_continuous_scale="Viridis",
#                 text_auto=True

#             )
#             fig_flows.update_layout(yaxis=dict(autorange="reversed"))
#             st.plotly_chart(fig_flows, width="stretch")

#         with col_flow_table:
#             st.markdown("**Flow Statistics**")
#             st.dataframe(top_flows, hide_index=True, width="stretch", height=400)

#         st.divider()

#         # --- SECTION B: TRAFFIC ANALYSIS (Specific to Magic) ---
#         st.subheader("📈 Magic Traffic Patterns")

#         # Hourly Analysis
#         df_final["hour"] = df_final["timestamp"].dt.floor("h")
#         hourly_counts = df_final.groupby("hour").size().reset_index(name="requests")
        
#         col_h_chart, col_h_table = st.columns([3, 1])
#         with col_h_chart:
#             fig_hourly = px.bar(hourly_counts, x="hour", y="requests", title="Hourly Load (Magic Requests Only)")
#             st.plotly_chart(fig_hourly, width="stretch")
#         with col_h_table:
#             st.markdown("**Top Busiest Hours**")
#             top_hours = hourly_counts.sort_values("requests", ascending=False).head(5)
#             top_hours["Time"] = top_hours["hour"].dt.strftime("%Y-%m-%d %H:00")
#             st.dataframe(top_hours[["Time", "requests"]], hide_index=True, width="stretch")

#         # --- SECTION C: PEAK LOAD (Specific to Magic) ---
#         st.subheader("⚡ Peak Load Analysis")
#         col_peak_1, col_peak_2 = st.columns(2)

#         # 1. Peak Seconds
#         with col_peak_1:
#             st.markdown("### Max Requests / Second")
#             peak_sec = df_final["timestamp"].dt.floor("s").value_counts().nlargest(10).reset_index()
#             peak_sec.columns = ["Time", "Requests"]
#             peak_sec["Time Str"] = peak_sec["Time"].dt.strftime("%H:%M:%S")

#             fig_peak_sec = px.bar(peak_sec, x="Requests", y="Time Str", orientation='h', title="Top 10 Seconds", color="Requests", color_continuous_scale="Reds",text_auto=True)
#             fig_peak_sec.update_layout(yaxis=dict(autorange="reversed"))
#             st.plotly_chart(fig_peak_sec, width="stretch")
            
#             with st.expander("Show Data Table"):
#                 st.dataframe(peak_sec[["Time Str", "Requests"]], hide_index=True, width="stretch")

#         # 2. Peak Minutes
#         with col_peak_2:
#             st.markdown("### Max Requests / Minute")
#             peak_min = df_final["timestamp"].dt.floor("min").value_counts().nlargest(10).reset_index()
#             peak_min.columns = ["Time", "Requests"]
#             peak_min["Time Str"] = peak_min["Time"].dt.strftime("%H:%M")

#             fig_peak_min = px.bar(peak_min, x="Requests", y="Time Str", orientation='h', title="Top 10 Minutes", color="Requests", color_continuous_scale="Oranges",text_auto=True)
#             fig_peak_min.update_layout(yaxis=dict(autorange="reversed"))
#             st.plotly_chart(fig_peak_min, width="stretch")

#             with st.expander("Show Data Table"):
#                 st.dataframe(peak_min[["Time Str", "Requests"]], hide_index=True, width="stretch")

#         # --- SECTION D: STATUS CODES (Specific to Magic) ---
#         st.divider()
#         col_stat_1, col_stat_2 = st.columns([1, 2])
        
#         with col_stat_1:
#             st.subheader("🚦 Status Codes")
#             if "sc-status" in df_final.columns:
#                 status_counts = df_final["sc-status"].value_counts().reset_index()
#                 status_counts.columns = ["Status", "Count"]
#                 fig_status = px.pie(status_counts, names="Status", values="Count", hole=0.4)
#                 st.plotly_chart(fig_status, width="stretch")

#         # --- SECTION E: RAW DATA EXPLORER ---
#         with col_stat_2:
#             st.subheader("🔍 Data Explorer")
#             st.markdown("Filter and inspect the raw decoded data.")
            
#             # Allow user to filter by specific flow in the table
#             all_flows = ["All"] + sorted(df_final['flow_name'].unique().tolist())
#             selected_flow = st.selectbox("Filter Data by Flow:", all_flows)
            
#             if selected_flow != "All":
#                 df_display = df_final[df_final['flow_name'] == selected_flow]
#             else:
#                 df_display = df_final

#             # Select useful columns to display
#             cols_to_show = ['date', 'time', 'flow_name', 'sc-status', 'time-taken', 'c-ip']
#             # Only include columns that actually exist in the log
#             valid_cols = [c for c in cols_to_show if c in df_display.columns]
            
#             st.dataframe(df_display[valid_cols], width="stretch", height=400)

# else:
#     st.info("Please upload a log file to begin analysis.")


# # V 2 - Full Flow Identifier (AppName + Arguments)
# import streamlit as st
# import pandas as pd
# import plotly.express as px

# # Page configuration
# st.set_page_config(page_title="MagicLog Analyzer", layout="wide", page_icon="🔮")

# st.title("🔮 MgWebRequester Log Analyzer")
# st.markdown("This dashboard focuses **exclusively** on `MgWebRequester.dll` traffic.")

# # --- 1. PARSING FUNCTION ---
# @st.cache_data
# def parse_log_file(uploaded_file):
#     content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
#     lines = content.splitlines()

#     fields = None
#     data_lines = []

#     for line in lines:
#         line = line.strip()
#         if not line:
#             continue
#         if line.startswith("#"):
#             if line.lower().startswith("#fields:"):
#                 fields = line.split(":", 1)[1].strip().split()
#             continue
#         data_lines.append(line)

#     if fields is None:
#         return None

#     rows = []
#     for ln in data_lines:
#         parts = ln.split()
#         if len(parts) < len(fields):
#             continue
#         rows.append(dict(zip(fields, parts)))

#     df = pd.DataFrame(rows)

#     if "date" in df.columns and "time" in df.columns:
#         df["timestamp"] = pd.to_datetime(df["date"] + " " + df["time"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
#         df = df.dropna(subset=["timestamp"])
#         df = df.sort_values("timestamp")
    
#     return df

# # --- 2. FILE UPLOADER ---
# uploaded_file = st.sidebar.file_uploader("Choose a Log File", type=["log", "txt"])

# if uploaded_file is not None:
#     with st.spinner("Parsing and Filtering for Magic requests..."):
#         df_raw = parse_log_file(uploaded_file)

#     if df_raw is None:
#         st.error("Header not found. Ensure W3C format.")
#     elif df_raw.empty:
#         st.warning("No data found in file.")
#     else:
#         # --- 3. FILTER & TRANSFORM LOGIC (MAGIC SPECIFIC) ---
        
#         # Check required columns
#         if "cs-uri-stem" not in df_raw.columns or "cs-uri-query" not in df_raw.columns:
#             st.error("Log file missing 'cs-uri-stem' or 'cs-uri-query' columns.")
#             st.stop()

#         # A. Filter specifically for MgWebRequester
#         df_magic = df_raw[df_raw["cs-uri-stem"].str.contains("MgWebRequester.dll", case=False, na=False)].copy()

#         if df_magic.empty:
#             st.warning("No 'MgWebRequester.dll' requests found in this log file.")
#             st.stop()

#         # B. Extract AppName AND Arguments
#         # 1. Extract appname
#         df_magic['extracted_app'] = df_magic['cs-uri-query'].str.extract(r"appname=([^&]*)")
#         df_magic['extracted_app'] = df_magic['extracted_app'].fillna("UnknownApp")

#         # 2. Extract arguments
#         df_magic['extracted_arg'] = df_magic['cs-uri-query'].str.extract(r"arguments=([^&]*)")
        
#         # 3. Decode %23 to #
#         df_magic['decoded_arg'] = df_magic['extracted_arg'].str.replace('%23', '#', regex=False)
#         df_magic['decoded_arg'] = df_magic['decoded_arg'].fillna("NoArgs")

#         # 4. Create Combined Identifier (Feature Request)
#         df_magic['full_flow_id'] = df_magic['extracted_app'] + " -> " + df_magic['decoded_arg']

#         # --- 4. SIDEBAR DATE FILTER ---
#         st.sidebar.header("Filters")
#         min_date = df_magic["timestamp"].min()
#         max_date = df_magic["timestamp"].max()
        
#         col1, col2 = st.sidebar.columns(2)
#         start_date = col1.date_input("Start Date", min_date.date())
#         end_date = col2.date_input("End Date", max_date.date())

#         mask = (df_magic["timestamp"].dt.date >= start_date) & (df_magic["timestamp"].dt.date <= end_date)
#         df_final = df_magic.loc[mask].copy()

#         # --- 5. DASHBOARD ---

#         # KPIs
#         total_reqs = len(df_final)
#         unique_flows = df_final['full_flow_id'].nunique()
#         errors = df_final[df_final['sc-status'].astype(str).str.startswith(('4', '5'))]
#         error_count = len(errors)

#         k1, k2, k3 = st.columns(3)
#         k1.metric("Total Magic Requests", f"{total_reqs:,}")
#         k2.metric("Unique Flows (App+Args)", f"{unique_flows:,}")
#         k3.metric("Error Responses (4xx/5xx)", f"{error_count:,}", delta_color="inverse")

#         st.divider()

#         # --- SECTION A: TOP COMBINED FLOWS ---
#         st.subheader("🏆 Top Magic Flows (AppName + Arguments)")
        
#         # Group by the combined ID
#         flow_counts = df_final["full_flow_id"].value_counts().reset_index()
#         flow_counts.columns = ["Flow Identifier", "Count"]
#         top_flows = flow_counts.head(15)

#         col_flow_chart, col_flow_table = st.columns([3, 1])
        
#         with col_flow_chart:
#             fig_flows = px.bar(
#                 top_flows, 
#                 x="Count", 
#                 y="Flow Identifier", 
#                 orientation='h', 
#                 title="Top 15 Most Executed Flows",
#                 text_auto=True, # Show numbers on bars
#                 color="Count",
#                 color_continuous_scale="Viridis"
#             )
#             fig_flows.update_layout(yaxis=dict(autorange="reversed"))
#             st.plotly_chart(fig_flows, width="stretch")

#         with col_flow_table:
#             st.markdown("**Flow Statistics**")
#             st.dataframe(top_flows, hide_index=True, width="stretch", height=400)

#         st.divider()

#         # --- SECTION B: TRAFFIC ANALYSIS ---
#         st.subheader("📈 Hourly Traffic Analysis")

#         # Hourly Analysis
#         df_final["hour"] = df_final["timestamp"].dt.floor("h")
#         hourly_counts = df_final.groupby("hour").size().reset_index(name="requests")
        
#         col_h_chart, col_h_table = st.columns([3, 1])
        
#         with col_h_chart:
#             # Added text_auto=True to show count on bars
#             fig_hourly = px.bar(
#                 hourly_counts, 
#                 x="hour", 
#                 y="requests", 
#                 title="Hourly Load (Magic Requests Only)",
#                 text_auto=True 
#             )
#             st.plotly_chart(fig_hourly, width="stretch")

#             # Feature: Expandable full records
#             with st.expander("📂 View All Hourly Data"):
#                 hourly_counts["Time Formatted"] = hourly_counts["hour"].dt.strftime("%Y-%m-%d %H:00")
#                 st.dataframe(hourly_counts[["Time Formatted", "requests"]], hide_index=True, width="stretch")

#         with col_h_table:
#             # Feature: Top 10 Busiest Hours
#             st.markdown("**🔥 Top 10 Busiest Hours**")
#             top_hours = hourly_counts.sort_values("requests", ascending=False).head(10)
#             top_hours["Time"] = top_hours["hour"].dt.strftime("%Y-%m-%d %H:00")
#             st.dataframe(top_hours[["Time", "requests"]], hide_index=True, width="stretch")

#         # --- SECTION C: PEAK LOAD ---
#         st.subheader("⚡ Peak Load Analysis")
#         col_peak_1, col_peak_2 = st.columns(2)

#         # 1. Peak Seconds
#         with col_peak_1:
#             st.markdown("### Max Requests / Second")
#             peak_sec = df_final["timestamp"].dt.floor("S").value_counts().nlargest(10).reset_index()
#             peak_sec.columns = ["Time", "Requests"]
#             peak_sec["Time Str"] = peak_sec["Time"].dt.strftime("%H:%M:%S")

#             fig_peak_sec = px.bar(peak_sec, x="Requests", y="Time Str", orientation='h', text_auto=True, color="Requests", color_continuous_scale="Reds")
#             fig_peak_sec.update_layout(yaxis=dict(autorange="reversed"))
#             st.plotly_chart(fig_peak_sec, width="stretch")
            
#         # 2. Peak Minutes
#         with col_peak_2:
#             st.markdown("### Max Requests / Minute")
#             peak_min = df_final["timestamp"].dt.floor("min").value_counts().nlargest(10).reset_index()
#             peak_min.columns = ["Time", "Requests"]
#             peak_min["Time Str"] = peak_min["Time"].dt.strftime("%H:%M")

#             fig_peak_min = px.bar(peak_min, x="Requests", y="Time Str", orientation='h', text_auto=True, color="Requests", color_continuous_scale="Oranges")
#             fig_peak_min.update_layout(yaxis=dict(autorange="reversed"))
#             st.plotly_chart(fig_peak_min, width="stretch")
        
#         # --- SECTION D: STATUS CODES (Specific to Magic) ---
#         st.divider()
#         col_stat_1, col_stat_2 = st.columns([1, 2])
        
#         with col_stat_1:
#             st.subheader("🚦 Status Codes")
#             if "sc-status" in df_final.columns:
#                 status_counts = df_final["sc-status"].value_counts().reset_index()
#                 status_counts.columns = ["Status", "Count"]
#                 fig_status = px.pie(status_counts, names="Status", values="Count", hole=0.4)
#                 st.plotly_chart(fig_status, width="stretch")

#         # --- SECTION D: DATA EXPLORER & FILTERS ---
#         st.divider()
#         st.subheader("🔍 Data Explorer")
        
#         col_filters_1, col_filters_2 = st.columns(2)
        
#         # Filter Logic
#         df_display = df_final.copy()

#         # 1. Flow Filter
#         with col_filters_1:
#             all_flows = sorted(df_final['full_flow_id'].unique().tolist())
#             selected_flow = st.selectbox("Filter by Flow (App -> Arg):", ["All"] + all_flows)
#             if selected_flow != "All":
#                 df_display = df_display[df_display['full_flow_id'] == selected_flow]

#         # 2. Status Code Filter (Feature Request)
#         with col_filters_2:
#             available_status = sorted(df_final['sc-status'].unique().tolist())
#             selected_status = st.multiselect("Filter by Status Code:", available_status,default=["500"])
#             if selected_status:
#                 df_display = df_display[df_display['sc-status'].isin(selected_status)]

#         st.markdown(f"**Showing {len(df_display)} records**")
        
#         # Select useful columns to display
#         cols_to_show = ['date', 'time', 'sc-status', 'time-taken', 'extracted_app', 'decoded_arg', 'c-ip']
#         # Only include columns that actually exist
#         valid_cols = [c for c in cols_to_show if c in df_display.columns]
        
#         st.dataframe(df_display[valid_cols], width="stretch", height=400)

# else:
#     st.info("Please upload a log file to begin analysis.")

# V 3 - Enhanced Error Analysis and Flow Breakdown

# import streamlit as st
# import pandas as pd
# import plotly.express as px

# # Page configuration
# st.set_page_config(page_title="MagicLog Analyzer", layout="wide", page_icon="🔮")

# st.title("🔮 IIS Log Analyzer")
# st.markdown("This dashboard focuses request load analysis.")

# # --- 1. PARSING FUNCTION ---
# @st.cache_data
# def parse_log_file(uploaded_file):
#     content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
#     lines = content.splitlines()

#     fields = None
#     data_lines = []

#     for line in lines:
#         line = line.strip()
#         if not line:
#             continue
#         if line.startswith("#"):
#             if line.lower().startswith("#fields:"):
#                 fields = line.split(":", 1)[1].strip().split()
#             continue
#         data_lines.append(line)

#     if fields is None:
#         return None

#     rows = []
#     for ln in data_lines:
#         parts = ln.split()
#         if len(parts) < len(fields):
#             continue
#         rows.append(dict(zip(fields, parts)))

#     df = pd.DataFrame(rows)

#     # Convert Timestamp
#     if "date" in df.columns and "time" in df.columns:
#         df["timestamp"] = pd.to_datetime(df["date"] + " " + df["time"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
#         df = df.dropna(subset=["timestamp"])
#         df = df.sort_values("timestamp")

#     # Convert time-taken to numeric (if exists)
#     if "time-taken" in df.columns:
#         df["time-taken"] = pd.to_numeric(df["time-taken"], errors="coerce").fillna(0).astype(int)
    
#     return df

# # --- 2. FILE UPLOADER ---
# uploaded_file = st.sidebar.file_uploader("Choose a Log File", type=["log", "txt"])

# if uploaded_file is not None:
#     with st.spinner("Parsing and Filtering for Magic requests..."):
#         df_raw = parse_log_file(uploaded_file)

#     if df_raw is None:
#         st.error("Header not found. Ensure W3C format.")
#     elif df_raw.empty:
#         st.warning("No data found in file.")
#     else:
#         # --- 3. FILTER & TRANSFORM LOGIC (MAGIC SPECIFIC) ---
        
#         # Check required columns
#         required_cols = ["cs-uri-stem", "cs-uri-query"]
#         if not all(col in df_raw.columns for col in required_cols):
#             st.error(f"Log file missing required columns: {required_cols}")
#             st.stop()

#         # A. Filter specifically for MgWebRequester
#         df_magic = df_raw[df_raw["cs-uri-stem"].str.contains("MgWebRequester.dll", case=False, na=False)].copy()

#         if df_magic.empty:
#             st.warning("No 'MgWebRequester.dll' requests found in this log file.")
#             st.stop()

#         # B. Extract AppName AND Arguments
#         df_magic['extracted_app'] = df_magic['cs-uri-query'].str.extract(r"appname=([^&]*)")
#         df_magic['extracted_app'] = df_magic['extracted_app'].fillna("UnknownApp")

#         df_magic['extracted_arg'] = df_magic['cs-uri-query'].str.extract(r"arguments=([^&]*)")
        
#         df_magic['decoded_arg'] = df_magic['extracted_arg'].str.replace('%23', '#', regex=False)
#         df_magic['decoded_arg'] = df_magic['decoded_arg'].fillna("NoArgs")

#         # Combined Identifier
#         df_magic['full_flow_id'] = df_magic['extracted_app'] + " -> " + df_magic['decoded_arg']

#         # --- 4. SIDEBAR DATE FILTER ---
#         st.sidebar.header("Filters")
#         min_date = df_magic["timestamp"].min()
#         max_date = df_magic["timestamp"].max()
        
#         col1, col2 = st.sidebar.columns(2)
#         start_date = col1.date_input("Start Date", min_date.date())
#         end_date = col2.date_input("End Date", max_date.date())

#         mask = (df_magic["timestamp"].dt.date >= start_date) & (df_magic["timestamp"].dt.date <= end_date)
#         df_final = df_magic.loc[mask].copy()

#         # --- 5. DASHBOARD ---

#         # KPIs
#         total_reqs = len(df_final)
#         unique_flows = df_final['full_flow_id'].nunique()
#         errors = df_final[df_final['sc-status'].astype(str).str.startswith(('4', '5'))]
#         error_count = len(errors)

#         k1, k2, k3 = st.columns(3)
#         k1.metric("Total Magic Requests", f"{total_reqs:,}")
#         k2.metric("Unique Flows (App+Args)", f"{unique_flows:,}")
#         k3.metric("Error Responses (4xx/5xx)", f"{error_count:,}", delta_color="inverse")

#         st.divider()
# # --- SECTION C: HOURLY TRAFFIC ---
#         st.subheader("📈 Hourly Traffic Analysis")

#         df_final["hour"] = df_final["timestamp"].dt.floor("h")
#         hourly_counts = df_final.groupby("hour").size().reset_index(name="requests")
        
#         col_h_chart, col_h_table = st.columns([3, 1])
        
#         with col_h_chart:
#             fig_hourly = px.bar(
#                 hourly_counts, 
#                 x="hour", 
#                 y="requests", 
#                 title="Hourly Load",
#                 text_auto=True 
#             )
#             st.plotly_chart(fig_hourly, width="stretch")

#             with st.expander("📂 View All Hourly Data"):
#                 hourly_counts["Time Formatted"] = hourly_counts["hour"].dt.strftime("%Y-%m-%d %H:00")
#                 st.dataframe(hourly_counts[["Time Formatted", "requests"]], hide_index=True, width="stretch")

#         with col_h_table:
#             st.markdown("**🔥 Top 10 Busiest Hours**")
#             top_hours = hourly_counts.sort_values("requests", ascending=False).head(10)
#             top_hours["Time"] = top_hours["hour"].dt.strftime("%Y-%m-%d %H:00")
#             st.dataframe(top_hours[["Time", "requests"]], hide_index=True, width="stretch")

#         st.divider()

#         # --- SECTION A: TOP COMBINED FLOWS ---
#         st.subheader("🏆 Top Magic Flows (Volume)")
        
#         flow_counts = df_final["full_flow_id"].value_counts().reset_index()
#         flow_counts.columns = ["Flow Identifier", "Count"]
#         top_flows = flow_counts.head(15)

#         col_flow_chart, col_flow_table = st.columns([3, 1])
        
#         with col_flow_chart:
#             fig_flows = px.bar(
#                 top_flows, 
#                 x="Count", 
#                 y="Flow Identifier", 
#                 orientation='h', 
#                 title="Top 15 Most Executed Flows",
#                 text_auto=True,
#                 color="Count",
#                 color_continuous_scale="Viridis"
#             )
#             fig_flows.update_layout(yaxis=dict(autorange="reversed"))
#             st.plotly_chart(fig_flows, width="stretch")

#         with col_flow_table:
#             st.markdown("**Flow Statistics**")
#             st.dataframe(top_flows, hide_index=True, width="stretch", height=400)

#         st.divider()
#         st.subheader("⏱️ API Performance Analysis")
#         st.markdown("Execution time statistics per API Flow (in **Seconds**).")

#         if "time-taken" in df_final.columns:
#             # 1. Aggregate Data (Raw data is in ms)
#             api_perf = df_final.groupby("full_flow_id")["time-taken"].agg(
#                 Min_Time="min",
#                 Max_Time="max",
#                 Avg_Time="mean",
#                 Request_Count="count"
#             ).reset_index()
            
#             # 2. CONVERT TO SECONDS (Divide by 1000)
#             cols_to_convert = ["Min_Time", "Max_Time", "Avg_Time"]
#             for col in cols_to_convert:
#                 api_perf[col] = (api_perf[col] / 1000).round(3)

#             col_perf_chart, col_perf_table = st.columns([2, 1])

#             with col_perf_chart:
#                 # Chart: Top 15 Slowest APIs by Average Time
#                 slowest_apis = api_perf.sort_values("Avg_Time", ascending=False).head(15)
                
#                 fig_perf = px.bar(
#                     slowest_apis,
#                     x="Avg_Time",
#                     y="full_flow_id",
#                     orientation='h',
#                     title="Top 15 Slowest APIs (Avg Seconds)",
#                     labels={"Avg_Time": "Avg Time (s)", "full_flow_id": "API Flow"},
#                     text_auto=True,
#                     color="Avg_Time",
#                     color_continuous_scale="Reds"
#                 )
#                 fig_perf.update_layout(yaxis=dict(autorange="reversed"))
#                 st.plotly_chart(fig_perf, width="stretch")

#             with col_perf_table:
#                 st.markdown("**Performance Table (Sortable)**")
#                 st.dataframe(
#                     api_perf, 
#                     hide_index=True, 
#                     width="stretch",
#                     column_config={
#                         "full_flow_id": "API Flow",
#                         "Request_Count": "Count",
#                         "Avg_Time": st.column_config.NumberColumn("Avg (sec)", format="%.3f"),
#                         "Min_Time": st.column_config.NumberColumn("Min (sec)", format="%.3f"),
#                         "Max_Time": st.column_config.NumberColumn("Max (sec)", format="%.3f"),
#                     }
#                 )
#         else:
#             st.warning("The 'time-taken' column was not found in the logs. Cannot calculate performance metrics.")

#         st.divider()

        
#         # --- SECTION D: PEAK LOAD ---
#         st.subheader("⚡ Peak Load Analysis")
#         col_peak_1, col_peak_2 = st.columns(2)

#         with col_peak_1:
#             st.markdown("### Max Requests / Second")
#             peak_sec = df_final["timestamp"].dt.floor("s").value_counts().nlargest(10).reset_index()
#             peak_sec.columns = ["Time", "Requests"]
#             peak_sec["Time Str"] = peak_sec["Time"].dt.strftime("%H:%M:%S")

#             fig_peak_sec = px.bar(peak_sec, x="Requests", y="Time Str", orientation='h', text_auto=True, color="Requests", color_continuous_scale="Reds")
#             fig_peak_sec.update_layout(yaxis=dict(autorange="reversed"))
#             st.plotly_chart(fig_peak_sec, width="stretch")
            
#         with col_peak_2:
#             st.markdown("### Max Requests / Minute")
#             peak_min = df_final["timestamp"].dt.floor("min").value_counts().nlargest(10).reset_index()
#             peak_min.columns = ["Time", "Requests"]
#             peak_min["Time Str"] = peak_min["Time"].dt.strftime("%H:%M")

#             fig_peak_min = px.bar(peak_min, x="Requests", y="Time Str", orientation='h', text_auto=True, color="Requests", color_continuous_scale="Oranges")
#             fig_peak_min.update_layout(yaxis=dict(autorange="reversed"))
#             st.plotly_chart(fig_peak_min, width="stretch")

#         # --- SECTION E: DATA EXPLORER ---
#         st.divider()
#         st.subheader("🔍 Data Explorer")
        
#         col_filters_1, col_filters_2 = st.columns(2)
        
#         df_display = df_final.copy()

#         with col_filters_1:
#             all_flows = sorted(df_final['full_flow_id'].unique().tolist())
#             selected_flow = st.selectbox("Filter by Flow (App -> Arg):", ["All"] + all_flows)
#             if selected_flow != "All":
#                 df_display = df_display[df_display['full_flow_id'] == selected_flow]

#         with col_filters_2:
#             available_status = sorted(df_final['sc-status'].unique().tolist())
#             selected_status = st.multiselect("Filter by Status Code:", available_status)
#             if selected_status:
#                 df_display = df_display[df_display['sc-status'].isin(selected_status)]

#         st.markdown(f"**Showing {len(df_display)} records**")
        
#         cols_to_show = ['date', 'time', 'sc-status', 'time-taken', 'extracted_app', 'decoded_arg', 'c-ip']
#         valid_cols = [c for c in cols_to_show if c in df_display.columns]
        
#         st.dataframe(df_display[valid_cols], width="stretch", height=400)

# else:
#     st.info("Please upload a log file to begin analysis.")

# # V 4 - Final Version with Enhanced Features and Comments
# import streamlit as st
# import pandas as pd
# import plotly.express as px

# # Page configuration
# st.set_page_config(page_title="MagicLog Analyzer", layout="wide", page_icon="🔮")

# st.title("🔮 MgWebRequester Log Analyzer")
# st.markdown("This dashboard focuses **exclusively** on `MgWebRequester.dll` traffic.")

# # --- 1. PARSING FUNCTION ---
# @st.cache_data
# def parse_log_file(uploaded_file, log_format):
#     content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
#     lines = content.splitlines()
#     rows = []

#     # --- FORMAT A: W3C EXTENDED (Space separated, #Fields header) ---
#     if log_format == "W3C Extended":
#         fields = None
#         data_lines = []
#         for line in lines:
#             line = line.strip()
#             if not line: continue
#             if line.startswith("#"):
#                 if line.lower().startswith("#fields:"):
#                     fields = line.split(":", 1)[1].strip().split()
#                 continue
#             data_lines.append(line)

#         if fields is None:
#             return None # Indicate error

#         for ln in data_lines:
#             parts = ln.split()
#             if len(parts) < len(fields): continue
#             rows.append(dict(zip(fields, parts)))

#         df = pd.DataFrame(rows)
        
#         # Date Parsing for W3C (Standard YYYY-MM-DD)
#         if "date" in df.columns and "time" in df.columns:
#             df["timestamp"] = pd.to_datetime(df["date"] + " " + df["time"], format="%Y-%m-%d %H:%M:%S", errors="coerce")

#     # --- FORMAT B: IIS CSV (Comma separated, Fixed columns) ---
#     elif log_format == "IIS (CSV)":
#         # Mapping based on the sample provided:
#         # IP, User, Date, Time, Service, Server, ServerIP, TimeTaken, BytesSent, BytesRecv, Status, WinStatus, Method, Stem, Query
#         column_map = [
#             "c-ip", "cs-username", "date", "time", "s-sitename", "s-computername", 
#             "s-ip", "time-taken", "sc-bytes", "cs-bytes", "sc-status", 
#             "sc-win32-status", "cs-method", "cs-uri-stem", "cs-uri-query"
#         ]
        
#         for line in lines:
#             line = line.strip()
#             if not line: continue
            
#             # Split by comma
#             parts = [p.strip() for p in line.split(',')]
            
#             # Ensure we have enough columns (Sample has 15 columns + trailing empty)
#             if len(parts) >= len(column_map):
#                 # Take only the mapped columns
#                 row_data = dict(zip(column_map, parts[:len(column_map)]))
#                 rows.append(row_data)

#         df = pd.DataFrame(rows)

#         # Date Parsing for IIS CSV (Sample uses MM/DD/YYYY e.g., 12/10/2025)
#         if "date" in df.columns and "time" in df.columns:
#             try:
#                 # Attempt to parse specific format from sample
#                 df["timestamp"] = pd.to_datetime(df["date"] + " " + df["time"], format="%m/%d/%Y %H:%M:%S", errors="coerce")
#             except:
#                 # Fallback
#                 df["timestamp"] = pd.to_datetime(df["date"] + " " + df["time"], errors="coerce")

#     # --- COMMON POST-PROCESSING ---
#     if df.empty:
#         return df

#     # Drop invalid dates and sort
#     df = df.dropna(subset=["timestamp"])
#     df = df.sort_values("timestamp")

#     # Convert time-taken to numeric (Integer) for calculations
#     if "time-taken" in df.columns:
#         df["time-taken"] = pd.to_numeric(df["time-taken"], errors="coerce").fillna(0).astype(int)
    
#     return df

# # --- 2. SIDEBAR CONFIGURATION ---
# st.sidebar.header("Configuration")

# # Log Format Selection
# log_fmt_option = st.sidebar.radio(
#     "Select Log Format",
#     ("W3C Extended", "IIS (CSV)"),
#     help="Select 'W3C' for space-delimited files with headers. Select 'IIS (CSV)' for comma-delimited files."
# )

# uploaded_file = st.sidebar.file_uploader(f"Upload {log_fmt_option} File", type=["log", "txt", "csv"])

# if uploaded_file is not None:
#     with st.spinner(f"Parsing {log_fmt_option} file..."):
#         df_raw = parse_log_file(uploaded_file, log_fmt_option)

#     if df_raw is None and log_fmt_option == "W3C Extended":
#         st.error("Header (#Fields) not found. Ensure file is W3C format or switch to IIS (CSV).")
#     elif df_raw is None or df_raw.empty:
#         st.warning("No valid data found. Check format selection.")
#     else:
#         # --- 3. FILTER & TRANSFORM LOGIC (MAGIC SPECIFIC) ---
        
#         required_cols = ["cs-uri-stem", "cs-uri-query"]
#         missing_cols = [c for c in required_cols if c not in df_raw.columns]
        
#         if missing_cols:
#             st.error(f"Missing columns for analysis: {missing_cols}")
#             st.write("Columns found:", df_raw.columns.tolist())
#             st.stop()

#         # A. Filter specifically for MgWebRequester
#         df_magic = df_raw[df_raw["cs-uri-stem"].str.contains("MgWebRequester.dll", case=False, na=False)].copy()

#         if df_magic.empty:
#             st.warning("No 'MgWebRequester.dll' requests found in this log file.")
#             st.stop()

#         # B. Extract AppName AND Arguments
#         df_magic['extracted_app'] = df_magic['cs-uri-query'].str.extract(r"appname=([^&]*)")
#         df_magic['extracted_app'] = df_magic['extracted_app'].fillna("UnknownApp")

#         df_magic['extracted_arg'] = df_magic['cs-uri-query'].str.extract(r"arguments=([^&]*)")
        
#         df_magic['decoded_arg'] = df_magic['extracted_arg'].str.replace('%23', '#', regex=False)
#         df_magic['decoded_arg'] = df_magic['decoded_arg'].fillna("NoArgs")

#         # Combined Identifier
#         df_magic['full_flow_id'] = df_magic['extracted_app'] + " -> " + df_magic['decoded_arg']

#         # --- 4. SIDEBAR DATE FILTER ---
#         st.sidebar.divider()
#         st.sidebar.header("Date Filters")
#         min_date = df_magic["timestamp"].min()
#         max_date = df_magic["timestamp"].max()
        
#         col1, col2 = st.sidebar.columns(2)
#         start_date = col1.date_input("Start Date", min_date.date())
#         end_date = col2.date_input("End Date", max_date.date())

#         mask = (df_magic["timestamp"].dt.date >= start_date) & (df_magic["timestamp"].dt.date <= end_date)
#         df_final = df_magic.loc[mask].copy()

#         # --- 5. DASHBOARD ---

#         # KPIs
#         total_reqs = len(df_final)
#         unique_flows = df_final['full_flow_id'].nunique()
#         errors = df_final[df_final['sc-status'].astype(str).str.startswith(('4', '5'))]
#         error_count = len(errors)

#         k1, k2, k3 = st.columns(3)
#         k1.metric("Total Magic Requests", f"{total_reqs:,}")
#         k2.metric("Unique Flows (App+Args)", f"{unique_flows:,}")
#         k3.metric("Error Responses (4xx/5xx)", f"{error_count:,}", delta_color="inverse")

#         st.divider()
#         # --- SECTION C: HOURLY TRAFFIC ---
#         st.subheader("📈 Hourly Traffic Analysis")

#         df_final["hour"] = df_final["timestamp"].dt.floor("h")
#         hourly_counts = df_final.groupby("hour").size().reset_index(name="requests")
        
#         col_h_chart, col_h_table = st.columns([3, 1])
        
#         with col_h_chart:
#             fig_hourly = px.bar(
#                 hourly_counts, 
#                 x="hour", 
#                 y="requests", 
#                 title="Hourly Load",
#                 text_auto=True 
#             )
#             st.plotly_chart(fig_hourly, width="stretch")

#             with st.expander("📂 View All Hourly Data"):
#                 hourly_counts["Time Formatted"] = hourly_counts["hour"].dt.strftime("%Y-%m-%d %H:00")
#                 st.dataframe(hourly_counts[["Time Formatted", "requests"]], hide_index=True, width="stretch")

#         with col_h_table:
#             st.markdown("**🔥 Top 10 Busiest Hours**")
#             top_hours = hourly_counts.sort_values("requests", ascending=False).head(10)
#             top_hours["Time"] = top_hours["hour"].dt.strftime("%Y-%m-%d %H:00")
#             st.dataframe(top_hours[["Time", "requests"]], hide_index=True, width="stretch")
#         st.divider()

#         # --- SECTION A: TOP COMBINED FLOWS ---
#         st.subheader("🏆 Top Magic Flows (Volume)")
        
#         flow_counts = df_final["full_flow_id"].value_counts().reset_index()
#         flow_counts.columns = ["Flow Identifier", "Count"]
#         top_flows = flow_counts.head(15)

#         col_flow_chart, col_flow_table = st.columns([3, 1])
        
#         with col_flow_chart:
#             fig_flows = px.bar(
#                 top_flows, 
#                 x="Count", 
#                 y="Flow Identifier", 
#                 orientation='h', 
#                 title="Top 15 Most Executed Flows",
#                 text_auto=True,
#                 color="Count",
#                 color_continuous_scale="Viridis"
#             )
#             fig_flows.update_layout(yaxis=dict(autorange="reversed"))
#             st.plotly_chart(fig_flows, width="stretch")

#         with col_flow_table:
#             st.markdown("**Flow Statistics**")
#             st.dataframe(top_flows, hide_index=True, width="stretch", height=400)

#         st.divider()

#         # --- SECTION B: API PERFORMANCE ANALYSIS ---
#         st.subheader("⏱️ API Performance Analysis")
#         st.markdown("Execution time statistics per API Flow (in **Seconds**).")

#         if "time-taken" in df_final.columns:
#             # 1. Aggregate Data (Raw data is in ms)
#             api_perf = df_final.groupby("full_flow_id")["time-taken"].agg(
#                 Min_Time="min",
#                 Max_Time="max",
#                 Avg_Time="mean",
#                 Request_Count="count"
#             ).reset_index()
            
#             # 2. CONVERT TO SECONDS (Divide by 1000)
#             cols_to_convert = ["Min_Time", "Max_Time", "Avg_Time"]
#             for col in cols_to_convert:
#                 api_perf[col] = (api_perf[col] / 1000).round(3)

#             col_perf_chart, col_perf_table = st.columns([2, 1])

#             with col_perf_chart:
#                 # Chart: Top 15 Slowest APIs by Average Time
#                 slowest_apis = api_perf.sort_values("Avg_Time", ascending=False).head(15)
                
#                 fig_perf = px.bar(
#                     slowest_apis,
#                     x="Avg_Time",
#                     y="full_flow_id",
#                     orientation='h',
#                     title="Top 15 Slowest APIs (Avg Seconds)",
#                     labels={"Avg_Time": "Avg Time (s)", "full_flow_id": "API Flow"},
#                     text_auto=True,
#                     color="Avg_Time",
#                     color_continuous_scale="Reds"
#                 )
#                 fig_perf.update_layout(yaxis=dict(autorange="reversed"))
#                 st.plotly_chart(fig_perf, width="stretch")

#             with col_perf_table:
#                 st.markdown("**Performance Table (Sortable)**")
#                 st.dataframe(
#                     api_perf, 
#                     hide_index=True, 
#                     width="stretch",
#                     column_config={
#                         "full_flow_id": "API Flow",
#                         "Request_Count": "Count",
#                         "Avg_Time": st.column_config.NumberColumn("Avg (sec)", format="%.3f"),
#                         "Min_Time": st.column_config.NumberColumn("Min (sec)", format="%.3f"),
#                         "Max_Time": st.column_config.NumberColumn("Max (sec)", format="%.3f"),
#                     }
#                 )
#         else:
#             st.warning("The 'time-taken' column was not found in the logs. Cannot calculate performance metrics.")

#         st.divider()

#         # --- SECTION D: PEAK LOAD ---
#         st.subheader("⚡ Peak Load Analysis")
#         col_peak_1, col_peak_2 = st.columns(2)

#         with col_peak_1:
#             st.markdown("### Max Requests / Second")
#             peak_sec = df_final["timestamp"].dt.floor("S").value_counts().nlargest(10).reset_index()
#             peak_sec.columns = ["Time", "Requests"]
#             peak_sec["Time Str"] = peak_sec["Time"].dt.strftime("%H:%M:%S")

#             fig_peak_sec = px.bar(peak_sec, x="Requests", y="Time Str", orientation='h', text_auto=True, color="Requests", color_continuous_scale="Reds")
#             fig_peak_sec.update_layout(yaxis=dict(autorange="reversed"))
#             st.plotly_chart(fig_peak_sec, width="stretch")
            
#         with col_peak_2:
#             st.markdown("### Max Requests / Minute")
#             peak_min = df_final["timestamp"].dt.floor("min").value_counts().nlargest(10).reset_index()
#             peak_min.columns = ["Time", "Requests"]
#             peak_min["Time Str"] = peak_min["Time"].dt.strftime("%H:%M")

#             fig_peak_min = px.bar(peak_min, x="Requests", y="Time Str", orientation='h', text_auto=True, color="Requests", color_continuous_scale="Oranges")
#             fig_peak_min.update_layout(yaxis=dict(autorange="reversed"))
#             st.plotly_chart(fig_peak_min, width="stretch")

#         # --- SECTION E: DATA EXPLORER ---
#         st.divider()
#         st.subheader("🔍 Data Explorer")
        
#         col_filters_1, col_filters_2 = st.columns(2)
        
#         df_display = df_final.copy()

#         with col_filters_1:
#             all_flows = sorted(df_final['full_flow_id'].unique().tolist())
#             selected_flow = st.selectbox("Filter by Flow (App -> Arg):", ["All"] + all_flows)
#             if selected_flow != "All":
#                 df_display = df_display[df_display['full_flow_id'] == selected_flow]

#         with col_filters_2:
#             available_status = sorted(df_final['sc-status'].unique().tolist())
#             selected_status = st.multiselect("Filter by Status Code:", available_status)
#             if selected_status:
#                 df_display = df_display[df_display['sc-status'].isin(selected_status)]

#         st.markdown(f"**Showing {len(df_display)} records**")
        
#         cols_to_show = ['date', 'time', 'sc-status', 'time-taken', 'extracted_app', 'decoded_arg', 'c-ip']
#         valid_cols = [c for c in cols_to_show if c in df_display.columns]
        
#         st.dataframe(df_display[valid_cols], width="stretch", height=400)

# else:
#     st.info("Please upload a log file to begin analysis.")


import streamlit as st
import pandas as pd
import plotly.express as px

# Page configuration
st.set_page_config(page_title="MagicLog Analyzer", layout="wide", page_icon="🔮")

st.title("🔮 IIS Log Analyzer")
st.markdown("This dashboard focuses IIS traffic analysis.")
st.markdown("ℹ️ **Multi-Server Support:** You can upload multiple log files (e.g., from a Load Balancer), and they will be merged into a single view.")

# --- 1. PARSING FUNCTION (Updated for Multiple Files) ---
@st.cache_data
def parse_multiple_files(uploaded_files, log_format):
    all_dfs = []
    
    # Progress bar setup since multiple files might take time
    progress_bar = st.progress(0)
    total_files = len(uploaded_files)

    for i, file in enumerate(uploaded_files):
        # Update progress
        progress_bar.progress((i + 1) / total_files)
        
        content = file.getvalue().decode("utf-8", errors="ignore")
        lines = content.splitlines()
        rows = []
        
        # --- PARSE SINGLE FILE ---
        
        # FORMAT A: W3C EXTENDED
        if log_format == "W3C Extended":
            fields = None
            data_lines = []
            for line in lines:
                line = line.strip()
                if not line: continue
                if line.startswith("#"):
                    if line.lower().startswith("#fields:"):
                        fields = line.split(":", 1)[1].strip().split()
                    continue
                data_lines.append(line)

            if fields:
                for ln in data_lines:
                    parts = ln.split()
                    if len(parts) < len(fields): continue
                    rows.append(dict(zip(fields, parts)))
                
                temp_df = pd.DataFrame(rows)
                
                # Standardize Date
                if "date" in temp_df.columns and "time" in temp_df.columns:
                    temp_df["timestamp"] = pd.to_datetime(temp_df["date"] + " " + temp_df["time"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
                    all_dfs.append(temp_df)

        # FORMAT B: IIS CSV
        elif log_format == "IIS (CSV)":
            column_map = [
                "c-ip", "cs-username", "date", "time", "s-sitename", "s-computername", 
                "s-ip", "time-taken", "sc-bytes", "cs-bytes", "sc-status", 
                "sc-win32-status", "cs-method", "cs-uri-stem", "cs-uri-query"
            ]
            
            for line in lines:
                line = line.strip()
                if not line: continue
                parts = [p.strip() for p in line.split(',')]
                
                if len(parts) >= len(column_map):
                    rows.append(dict(zip(column_map, parts[:len(column_map)])))

            if rows:
                temp_df = pd.DataFrame(rows)
                
                # Flexible Date Parsing
                if "date" in temp_df.columns and "time" in temp_df.columns:
                    try:
                        temp_df["timestamp"] = pd.to_datetime(temp_df["date"] + " " + temp_df["time"], format="%m/%d/%Y %H:%M:%S", errors="coerce")
                    except:
                        temp_df["timestamp"] = pd.to_datetime(temp_df["date"] + " " + temp_df["time"], errors="coerce")
                
                all_dfs.append(temp_df)

    progress_bar.empty() # Remove bar when done

    if not all_dfs:
        return None

    # --- MERGE ALL FILES ---
    # Concatenate all individual file dataframes
    final_df = pd.concat(all_dfs, ignore_index=True)

    # --- COMMON POST-PROCESSING ---
    if final_df.empty:
        return final_df

    # Drop invalid dates and sort by time (Crucial for merging different server logs)
    final_df = final_df.dropna(subset=["timestamp"])
    final_df = final_df.sort_values("timestamp")

    # Convert time-taken to numeric
    if "time-taken" in final_df.columns:
        final_df["time-taken"] = pd.to_numeric(final_df["time-taken"], errors="coerce").fillna(0).astype(int)
    
    return final_df

# --- 2. SIDEBAR CONFIGURATION ---
st.sidebar.header("Configuration")

# Log Format Selection
log_fmt_option = st.sidebar.radio(
    "Select Log Format",
    ("W3C Extended", "IIS (CSV)"),
    help="Select 'W3C' for space-delimited files. Select 'IIS (CSV)' for comma-delimited."
)

# File Uploader (Accept Multiple Files = True)
uploaded_files = st.sidebar.file_uploader(
    f"Upload {log_fmt_option} File(s)", 
    type=["log", "txt", "csv"], 
    accept_multiple_files=True  # <--- ENABLED
)

if uploaded_files:
    with st.spinner(f"Merging and Parsing {len(uploaded_files)} file(s)..."):
        df_raw = parse_multiple_files(uploaded_files, log_fmt_option)

    if df_raw is None:
        st.error("No valid data parsed. Check log format selection.")
    elif df_raw.empty:
        st.warning("Data found, but empty after processing.")
    else:
        # --- 3. FILTER & TRANSFORM LOGIC (MAGIC SPECIFIC) ---
        
        required_cols = ["cs-uri-stem", "cs-uri-query"]
        missing_cols = [c for c in required_cols if c not in df_raw.columns]
        
        if missing_cols:
            st.error(f"Missing columns for analysis: {missing_cols}")
            st.stop()

        # A. Filter specifically for MgWebRequester
        df_magic = df_raw[df_raw["cs-uri-stem"].str.contains("MgWebRequester.dll", case=False, na=False)].copy()

        if df_magic.empty:
            st.warning("No 'MgWebRequester.dll' requests found in the uploaded logs.")
            st.stop()

        # B. Extract AppName AND Arguments
        df_magic['extracted_app'] = df_magic['cs-uri-query'].str.extract(r"appname=([^&]*)")
        df_magic['extracted_app'] = df_magic['extracted_app'].fillna("UnknownApp")

        df_magic['extracted_arg'] = df_magic['cs-uri-query'].str.extract(r"arguments=([^&]*)")
        
        df_magic['decoded_arg'] = df_magic['extracted_arg'].str.replace('%23', '#', regex=False)
        df_magic['decoded_arg'] = df_magic['decoded_arg'].fillna("NoArgs")

        # Combined Identifier
        df_magic['full_flow_id'] = df_magic['extracted_app'] + " -> " + df_magic['decoded_arg']

        # --- 4. SIDEBAR DATE FILTER ---
        st.sidebar.divider()
        st.sidebar.header("Date Filters")
        min_date = df_magic["timestamp"].min()
        max_date = df_magic["timestamp"].max()
        
        col1, col2 = st.sidebar.columns(2)
        start_date = col1.date_input("Start Date", min_date.date())
        end_date = col2.date_input("End Date", max_date.date())

        mask = (df_magic["timestamp"].dt.date >= start_date) & (df_magic["timestamp"].dt.date <= end_date)
        df_final = df_magic.loc[mask].copy()

        # --- 5. DASHBOARD ---

        # KPIs
        total_reqs = len(df_final)
        unique_flows = df_final['full_flow_id'].nunique()
        errors = df_final[df_final['sc-status'].astype(str).str.startswith(('4', '5'))]
        error_count = len(errors)
        
        # Show file count metric
        k0, k1, k2, k3 = st.columns(4)
        k0.metric("Files Merged", len(uploaded_files))
        k1.metric("Total Magic Requests", f"{total_reqs:,}")
        k2.metric("Unique Flows (App+Args)", f"{unique_flows:,}")
        k3.metric("Error Responses (4xx/5xx)", f"{error_count:,}", delta_color="inverse")

        st.divider()

         # --- SECTION C: HOURLY TRAFFIC ---
        st.subheader("📈 Hourly Traffic Analysis")

        df_final["hour"] = df_final["timestamp"].dt.floor("h")
        hourly_counts = df_final.groupby("hour").size().reset_index(name="requests")
        
        col_h_chart, col_h_table = st.columns([3, 1])
        
        with col_h_chart:
            fig_hourly = px.bar(
                hourly_counts, 
                x="hour", 
                y="requests", 
                title="Hourly Load (Combined)",
                text_auto=True 
            )
            st.plotly_chart(fig_hourly, width="stretch")

            with st.expander("📂 View All Hourly Data"):
                hourly_counts["Time Formatted"] = hourly_counts["hour"].dt.strftime("%Y-%m-%d %H:00")
                st.dataframe(hourly_counts[["Time Formatted", "requests"]], hide_index=True, width="stretch")

        with col_h_table:
            st.markdown("**🔥 Top 10 Busiest Hours**")
            top_hours = hourly_counts.sort_values("requests", ascending=False).head(10)
            top_hours["Time"] = top_hours["hour"].dt.strftime("%Y-%m-%d %H:00")
            st.dataframe(top_hours[["Time", "requests"]], hide_index=True, width="stretch")


        # --- SECTION A: TOP COMBINED FLOWS ---
        st.subheader("🏆 Top Magic Flows (Volume)")
        
        flow_counts = df_final["full_flow_id"].value_counts().reset_index()
        flow_counts.columns = ["Flow Identifier", "Count"]
        top_flows = flow_counts.head(15)

        col_flow_chart, col_flow_table = st.columns([3, 1])
        
        with col_flow_chart:
            fig_flows = px.bar(
                top_flows, 
                x="Count", 
                y="Flow Identifier", 
                orientation='h', 
                title="Top 15 Most Executed Flows",
                text_auto=True,
                color="Count",
                color_continuous_scale="Viridis"
            )
            fig_flows.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig_flows, width="stretch")

        with col_flow_table:
            st.markdown("**Flow Statistics**")
            st.dataframe(top_flows, hide_index=True, width="stretch", height=400)

        st.divider()

        # --- SECTION B: API PERFORMANCE ANALYSIS ---
        st.subheader("⏱️ API Performance Analysis")
        st.markdown("Execution time statistics per API Flow (in **Seconds**).")

        if "time-taken" in df_final.columns:
            # 1. Aggregate Data
            api_perf = df_final.groupby("full_flow_id")["time-taken"].agg(
                Min_Time="min",
                Max_Time="max",
                Avg_Time="mean",
                Request_Count="count"
            ).reset_index()
            
            # 2. CONVERT TO SECONDS
            cols_to_convert = ["Min_Time", "Max_Time", "Avg_Time"]
            for col in cols_to_convert:
                api_perf[col] = (api_perf[col] / 1000).round(3)

            col_perf_chart, col_perf_table = st.columns([2, 1])

            with col_perf_chart:
                slowest_apis = api_perf.sort_values("Avg_Time", ascending=False).head(15)
                
                fig_perf = px.bar(
                    slowest_apis,
                    x="Avg_Time",
                    y="full_flow_id",
                    orientation='h',
                    title="Top 15 Slowest APIs (Avg Seconds)",
                    labels={"Avg_Time": "Avg Time (s)", "full_flow_id": "API Flow"},
                    text_auto=True,
                    color="Avg_Time",
                    color_continuous_scale="Reds"
                )
                fig_perf.update_layout(yaxis=dict(autorange="reversed"))
                st.plotly_chart(fig_perf, width="stretch")

            with col_perf_table:
                st.markdown("**Performance Table**")
                st.dataframe(
                    api_perf, 
                    hide_index=True, 
                    width="stretch",
                    column_config={
                        "full_flow_id": "API Flow",
                        "Request_Count": "Count",
                        "Avg_Time": st.column_config.NumberColumn("Avg (sec)", format="%.3f"),
                        "Min_Time": st.column_config.NumberColumn("Min (sec)", format="%.3f"),
                        "Max_Time": st.column_config.NumberColumn("Max (sec)", format="%.3f"),
                    }
                )
        else:
            st.warning("The 'time-taken' column was not found. Cannot calculate performance metrics.")

        st.divider()

       
        # --- SECTION D: PEAK LOAD ---
        st.subheader("⚡ Peak Load Analysis")
        col_peak_1, col_peak_2 = st.columns(2)

        with col_peak_1:
            st.markdown("### Max Requests / Second")
            peak_sec = df_final["timestamp"].dt.floor("S").value_counts().nlargest(10).reset_index()
            peak_sec.columns = ["Time", "Requests"]
            peak_sec["Time Str"] = peak_sec["Time"].dt.strftime("%H:%M:%S")

            fig_peak_sec = px.bar(peak_sec, x="Requests", y="Time Str", orientation='h', text_auto=True, color="Requests", color_continuous_scale="Reds")
            fig_peak_sec.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig_peak_sec, width="stretch")
            
        with col_peak_2:
            st.markdown("### Max Requests / Minute")
            peak_min = df_final["timestamp"].dt.floor("min").value_counts().nlargest(10).reset_index()
            peak_min.columns = ["Time", "Requests"]
            peak_min["Time Str"] = peak_min["Time"].dt.strftime("%H:%M")

            fig_peak_min = px.bar(peak_min, x="Requests", y="Time Str", orientation='h', text_auto=True, color="Requests", color_continuous_scale="Oranges")
            fig_peak_min.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig_peak_min, width="stretch")

        # --- SECTION E: DATA EXPLORER ---
        st.divider()
        st.subheader("🔍 Data Explorer")
        
        col_filters_1, col_filters_2 = st.columns(2)
        
        df_display = df_final.copy()

        with col_filters_1:
            all_flows = sorted(df_final['full_flow_id'].unique().tolist())
            selected_flow = st.selectbox("Filter by Flow (App -> Arg):", ["All"] + all_flows)
            if selected_flow != "All":
                df_display = df_display[df_display['full_flow_id'] == selected_flow]

        with col_filters_2:
            available_status = sorted(df_final['sc-status'].unique().tolist())
            selected_status = st.multiselect("Filter by Status Code:", available_status)
            if selected_status:
                df_display = df_display[df_display['sc-status'].isin(selected_status)]

        st.markdown(f"**Showing {len(df_display)} records**")
        
        cols_to_show = ['date', 'time', 'sc-status', 'time-taken', 'extracted_app', 'decoded_arg', 'c-ip', 's-ip']
        valid_cols = [c for c in cols_to_show if c in df_display.columns]
        
        st.dataframe(df_display[valid_cols], width="stretch", height=400)

else:
    st.info("Please upload log file(s) to begin analysis.")