# IIS Log Analyzer (Specialized for MgWebRequester)

A powerful, interactive Streamlit dashboard designed to parse, visualize, and analyze IIS server logs. 

While it accepts standard IIS logs, the analysis logic is **specifically tuned for Magic xpa/xpi web requests** (`MgWebRequester.dll`). It extracts application names and decodes argument flows to provide deep insights into API usage and performance.

## 🚀 Key Features

### 1. Multi-Format & Multi-Server Support
*   **Dual Format:** Supports both **W3C Extended** (standard space-delimited) and **IIS CSV** (comma-delimited) log formats.
*   **Merge Capabilities:** Upload multiple log files at once (e.g., from a Load Balanced environment). The tool automatically merges them and sorts records chronologically.

### 2. Advanced Parsing Logic
*   **Magic Filtering:** Automatically filters the dataset to focus exclusively on requests containing `MgWebRequester.dll`.
*   **Flow Decoding:** Extracts the `appname` and `arguments` from the query string.
*   **Character Normalization:** Automatically replaces URL-encoded characters (like `%23` to `#`) for readable flow names.

### 3. Interactive Visualizations
*   **Top Flows:** Bar charts showing the most frequently called Application -> Argument combinations.
*   **Hourly Traffic:** View request volume trends over time with expandable data tables.
*   **Peak Load Analysis:** Identify the single busiest **Second** and **Minute** in your log history (Requests per Second/Minute).

### 4. API Performance Metrics
*   **Execution Time:** Calculates Min, Max, and Average execution time for every API call.
*   **Seconds Conversion:** Automatically converts `time-taken` (milliseconds) into **Seconds** for easier readability.
*   **Slowest APIs:** A dedicated chart highlights the top 15 slowest performing flows.

### 5. Data Explorer
*   **Drill Down:** Filter raw log data by specific **Flows** (App/Arguments) or **HTTP Status Codes** (e.g., 500 Errors).
*   **Export:** View detailed records including Client IP, Server IP, Time Taken, and Status.

---

## 🛠️ Installation & Usage

### Prerequisites
You need Python installed. Then install the required libraries:

```bash
pip install streamlit pandas plotly
