

# import streamlit as st
# import pandas as pd
# import plotly.express as px

# # Page configuration
# st.set_page_config(page_title="MagicLog Analyzer", layout="wide", page_icon="🔮")

# st.title("🔮 IIS Log Analyzer")
# st.markdown("This dashboard focuses IIS traffic analysis.")
# st.markdown("ℹ️ **Multi-Server Support:** You can upload multiple log files (e.g., from a Load Balancer), and they will be merged into a single view.")

# # --- 1. PARSING FUNCTION (Updated for Multiple Files) ---
# @st.cache_data
# def parse_multiple_files(uploaded_files, log_format):
#     all_dfs = []
    
#     # Progress bar setup since multiple files might take time
#     progress_bar = st.progress(0)
#     total_files = len(uploaded_files)

#     for i, file in enumerate(uploaded_files):
#         # Update progress
#         progress_bar.progress((i + 1) / total_files)
        
#         content = file.getvalue().decode("utf-8", errors="ignore")
#         lines = content.splitlines()
#         rows = []
        
#         # --- PARSE SINGLE FILE ---
        
#         # FORMAT A: W3C EXTENDED
#         if log_format == "W3C Extended":
#             fields = None
#             data_lines = []
#             for line in lines:
#                 line = line.strip()
#                 if not line: continue
#                 if line.startswith("#"):
#                     if line.lower().startswith("#fields:"):
#                         fields = line.split(":", 1)[1].strip().split()
#                     continue
#                 data_lines.append(line)

#             if fields:
#                 for ln in data_lines:
#                     parts = ln.split()
#                     if len(parts) < len(fields): continue
#                     rows.append(dict(zip(fields, parts)))
                
#                 temp_df = pd.DataFrame(rows)
                
#                 # Standardize Date
#                 if "date" in temp_df.columns and "time" in temp_df.columns:
#                     temp_df["timestamp"] = pd.to_datetime(temp_df["date"] + " " + temp_df["time"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
#                     all_dfs.append(temp_df)

#         # FORMAT B: IIS CSV
#         elif log_format == "IIS (CSV)":
#             column_map = [
#                 "c-ip", "cs-username", "date", "time", "s-sitename", "s-computername", 
#                 "s-ip", "time-taken", "sc-bytes", "cs-bytes", "sc-status", 
#                 "sc-win32-status", "cs-method", "cs-uri-stem", "cs-uri-query"
#             ]
            
#             for line in lines:
#                 line = line.strip()
#                 if not line: continue
#                 parts = [p.strip() for p in line.split(',')]
                
#                 if len(parts) >= len(column_map):
#                     rows.append(dict(zip(column_map, parts[:len(column_map)])))

#             if rows:
#                 temp_df = pd.DataFrame(rows)
                
#                 # Flexible Date Parsing
#                 if "date" in temp_df.columns and "time" in temp_df.columns:
#                     try:
#                         temp_df["timestamp"] = pd.to_datetime(temp_df["date"] + " " + temp_df["time"], format="%m/%d/%Y %H:%M:%S", errors="coerce")
#                     except:
#                         temp_df["timestamp"] = pd.to_datetime(temp_df["date"] + " " + temp_df["time"], errors="coerce")
                
#                 all_dfs.append(temp_df)

#     progress_bar.empty() # Remove bar when done

#     if not all_dfs:
#         return None

#     # --- MERGE ALL FILES ---
#     # Concatenate all individual file dataframes
#     final_df = pd.concat(all_dfs, ignore_index=True)

#     # --- COMMON POST-PROCESSING ---
#     if final_df.empty:
#         return final_df

#     # Drop invalid dates and sort by time (Crucial for merging different server logs)
#     final_df = final_df.dropna(subset=["timestamp"])
#     final_df = final_df.sort_values("timestamp")

#     # Convert time-taken to numeric
#     if "time-taken" in final_df.columns:
#         final_df["time-taken"] = pd.to_numeric(final_df["time-taken"], errors="coerce").fillna(0).astype(int)
    
#     return final_df

# # --- 2. SIDEBAR CONFIGURATION ---
# st.sidebar.header("Configuration")

# # Log Format Selection
# log_fmt_option = st.sidebar.radio(
#     "Select Log Format",
#     ("W3C Extended", "IIS (CSV)"),
#     help="Select 'W3C' for space-delimited files. Select 'IIS (CSV)' for comma-delimited."
# )

# # File Uploader (Accept Multiple Files = True)
# uploaded_files = st.sidebar.file_uploader(
#     f"Upload {log_fmt_option} File(s)", 
#     type=["log", "txt", "csv"], 
#     accept_multiple_files=True  # <--- ENABLED
# )

# if uploaded_files:
#     with st.spinner(f"Merging and Parsing {len(uploaded_files)} file(s)..."):
#         df_raw = parse_multiple_files(uploaded_files, log_fmt_option)

#     if df_raw is None:
#         st.error("No valid data parsed. Check log format selection.")
#     elif df_raw.empty:
#         st.warning("Data found, but empty after processing.")
#     else:
#         # --- 3. FILTER & TRANSFORM LOGIC (MAGIC SPECIFIC) ---
        
#         required_cols = ["cs-uri-stem", "cs-uri-query"]
#         missing_cols = [c for c in required_cols if c not in df_raw.columns]
        
#         if missing_cols:
#             st.error(f"Missing columns for analysis: {missing_cols}")
#             st.stop()

#         # A. Filter specifically for MgWebRequester
#         df_magic = df_raw[df_raw["cs-uri-stem"].str.contains("MgWebRequester.dll", case=False, na=False)].copy()

#         if df_magic.empty:
#             st.warning("No 'MgWebRequester.dll' requests found in the uploaded logs.")
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
        
#         # Show file count metric
#         k0, k1, k2, k3 = st.columns(4)
#         k0.metric("Files Merged", len(uploaded_files))
#         k1.metric("Total Magic Requests", f"{total_reqs:,}")
#         k2.metric("Unique Flows (App+Args)", f"{unique_flows:,}")
#         k3.metric("Error Responses (4xx/5xx)", f"{error_count:,}", delta_color="inverse")

#         st.divider()

#          # --- SECTION C: HOURLY TRAFFIC ---
#         st.subheader("📈 Hourly Traffic Analysis")

#         df_final["hour"] = df_final["timestamp"].dt.floor("h")
#         hourly_counts = df_final.groupby("hour").size().reset_index(name="requests")
        
#         col_h_chart, col_h_table = st.columns([3, 1])
        
#         with col_h_chart:
#             fig_hourly = px.bar(
#                 hourly_counts, 
#                 x="hour", 
#                 y="requests", 
#                 title="Hourly Load (Combined)",
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
#             # 1. Aggregate Data
#             api_perf = df_final.groupby("full_flow_id")["time-taken"].agg(
#                 Min_Time="min",
#                 Max_Time="max",
#                 Avg_Time="mean",
#                 Request_Count="count"
#             ).reset_index()
            
#             # 2. CONVERT TO SECONDS
#             cols_to_convert = ["Min_Time", "Max_Time", "Avg_Time"]
#             for col in cols_to_convert:
#                 api_perf[col] = (api_perf[col] / 1000).round(3)

#             col_perf_chart, col_perf_table = st.columns([2, 1])

#             with col_perf_chart:
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
#                 st.markdown("**Performance Table**")
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
#             st.warning("The 'time-taken' column was not found. Cannot calculate performance metrics.")

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
        
#         cols_to_show = ['date', 'time', 'sc-status', 'time-taken', 'extracted_app', 'decoded_arg', 'c-ip', 's-ip']
#         valid_cols = [c for c in cols_to_show if c in df_display.columns]
        
#         st.dataframe(df_display[valid_cols], width="stretch", height=400)

# else:
#     st.info("Please upload log file(s) to begin analysis.")
import streamlit as st
import pandas as pd
import plotly.express as px

# Page configuration
st.set_page_config(page_title="IIS Log Analyzer", layout="wide", page_icon="🔮")

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
        
        # Helper column for Date Grouping
        df_magic['date_str'] = df_magic['timestamp'].dt.strftime('%Y-%m-%d')

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
            
        # --- [NEW] SECTION A.1: TOP FLOWS BY DATE ---
        st.subheader("📅 Top Flows Trends (Daily)")
        st.markdown("Shows the daily volume of the **Top 10 Flows** to identify usage trends over time.")
        
        # 1. Identify Top 10 Flows overall
        top_10_flow_names = flow_counts.head(10)["Flow Identifier"].tolist()
        
        # 2. Filter data for only these flows
        df_top_flows = df_final[df_final["full_flow_id"].isin(top_10_flow_names)]
        
        # 3. Group by Date and Flow
        daily_flow_counts = df_top_flows.groupby(['date_str', 'full_flow_id']).size().reset_index(name='Requests')
        
        # 4. Plot Stacked Bar Chart
        fig_daily_flows = px.bar(
            daily_flow_counts,
            x="date_str",
            y="Requests",
            color="full_flow_id",
            title="Top 10 Magic Flows by Date",
            labels={"date_str": "Date", "full_flow_id": "Flow Name"},
            barmode='stack'
        )
        st.plotly_chart(fig_daily_flows, width="stretch")

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
            
            # --- [NEW] SECTION B.1: EXECUTION TIME PER DAY ---
            st.subheader("📅 Daily Performance Trends (Latency)")
            st.markdown("Tracks the **Min**, **Max**, and **Average** execution times per day (in Seconds).")
            
            # 1. Group by Date and Aggregate
            daily_perf_trends = df_final.groupby('date_str')['time-taken'].agg(['min', 'max', 'mean']).reset_index()
            
            # 2. Convert to Seconds
            daily_perf_trends['min'] = (daily_perf_trends['min'] / 1000).round(3)
            daily_perf_trends['max'] = (daily_perf_trends['max'] / 1000).round(3)
            daily_perf_trends['mean'] = (daily_perf_trends['mean'] / 1000).round(3)
            
            # 3. Melt for Plotly (to have multiple lines)
            daily_perf_melted = daily_perf_trends.melt(id_vars='date_str', value_vars=['min', 'max', 'mean'], var_name='Metric', value_name='Time (sec)')
            
            # 4. Plot Line Chart
            fig_daily_perf = px.line(
                daily_perf_melted,
                x='date_str',
                y='Time (sec)',
                color='Metric',
                title="Daily Min/Max/Avg Execution Time",
                markers=True,
                labels={"date_str": "Date"}
            )
            st.plotly_chart(fig_daily_perf, width="stretch")

        else:
            st.warning("The 'time-taken' column was not found. Cannot calculate performance metrics.")

        st.divider()

       
        # --- SECTION D: PEAK LOAD ---
        st.subheader("⚡ Peak Load Analysis")
        col_peak_1, col_peak_2 = st.columns(2)

        with col_peak_1:
            st.markdown("### Max Requests / Second")
            peak_sec = df_final["timestamp"].dt.floor("s").value_counts().nlargest(10).reset_index()
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

        # --- [NEW] SECTION D.1: DAILY LOAD INTENSITY ---
        st.subheader("📅 Daily Load Intensity (Requests per Minute Stats)")
        st.markdown("This chart analyzes the **Load Intensity** for each day. It calculates the requests per minute, then finds the **Highest (Max)**, **Lowest (Min)**, and **Average** load for that specific day.")
        
        # 1. Resample to 1-Minute buckets to get load
        # Use simple floor and group, faster than set_index for large datasets
        df_final['minute_bucket'] = df_final['timestamp'].dt.floor('min')
        load_per_minute = df_final.groupby('minute_bucket').size().reset_index(name='req_count')
        load_per_minute['date_str'] = load_per_minute['minute_bucket'].dt.strftime('%Y-%m-%d')
        
        # 2. Group by Date to get Min/Max/Avg of the minute buckets
        daily_load_stats = load_per_minute.groupby('date_str')['req_count'].agg(['min', 'max', 'mean']).reset_index()
        daily_load_stats['mean'] = daily_load_stats['mean'].round(1)
        
        # 3. Melt for visualization
        daily_load_melted = daily_load_stats.melt(id_vars='date_str', value_vars=['min', 'max', 'mean'], var_name='Metric', value_name='Requests per Minute')
        
        # 4. Plot Trend Graph
        fig_daily_load = px.line(
            daily_load_melted,
            x='date_str',
            y='Requests per Minute',
            color='Metric',
            title="Daily Max/Min/Avg Requests per Minute",
            markers=True,
            labels={"date_str": "Date"}
        )
        # Add opacity styling
        fig_daily_load.update_traces(opacity=0.8, line=dict(width=3))
        st.plotly_chart(fig_daily_load, width="stretch")

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