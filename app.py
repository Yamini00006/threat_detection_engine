# app.py
import os
import re
import json
import streamlit as st
import pandas as pd
from groq import Groq

# ------------------- CONFIGURATION -------------------
st.set_page_config(page_title="AI-Powered Mail & URL Threat Detection Engine", layout="wide")

# Load Groq API key
api_key = (
    os.environ.get("GROQ_API_KEY")
    or (st.secrets.get("GROQ_API_KEY") if "GROQ_API_KEY" in st.secrets else None)
)

if not api_key:
    st.warning("⚠️ GROQ_API_KEY not found. Please set it as an environment variable or in Streamlit secrets.")
    st.stop()

# Initialize Groq client
client = Groq(api_key=api_key)

# ------------------- LOAD AVAILABLE MODELS -------------------
try:
    models_response = client.models.list()

    if hasattr(models_response, "data"):
        available_models = [m.id for m in models_response.data]
    elif isinstance(models_response, dict) and "data" in models_response:
        available_models = [m["id"] for m in models_response["data"]]
    else:
        available_models = []

    if not available_models:
        available_models = ["llama3-8b-8192"]  # default fallback model

except Exception as e:
    st.warning(f"⚠️ Error fetching model list: {e}")
    available_models = ["llama3-8b-8192"]

# ------------------- REGEX EXTRACTORS -------------------
def extract_indicators(text: str):
    """Extract URLs, IPs, and email addresses from input text."""
    urls = re.findall(r"https?://[^\s]+", text)
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)

    return {
        "urls": list(set(urls)),
        "ips": list(set(ips)),
        "emails": list(set(emails)),
    }

# ------------------- MAIN ANALYSIS FUNCTION -------------------
def analyze_threats_stream(text_input: str, model: str = "llama3-8b-8192"):
    """
    Stream Groq model output progressively for real-time display.
    Includes automatic truncation and IOC extraction.
    """
    # ---- Step 1: Extract Indicators ----
    indicators = extract_indicators(text_input)

    # ---- Step 2: Handle long text ----
    max_chars = 5000
    if len(text_input) > max_chars:
        truncated = text_input[:3000] + "\n...[TRUNCATED]...\n" + text_input[-1500:]
        text_input = (
            f"The following input was too long and was truncated for analysis.\n\n"
            f"{truncated}"
        )

    # ---- Step 3: Add extracted indicators to context ----
    indicator_summary = (
        f"\n\nExtracted Indicators:\n"
        f"- URLs: {', '.join(indicators['urls']) or 'None'}\n"
        f"- IPs: {', '.join(indicators['ips']) or 'None'}\n"
        f"- Emails: {', '.join(indicators['emails']) or 'None'}\n"
    )

    full_input = text_input + indicator_summary

    # ---- Step 4: System prompt ----
    system_prompt = (
        "You are a cybersecurity threat detection assistant. "
        "Analyze the input text for phishing, spam, or malicious content. "
        "Use any extracted URLs, IPs, or emails as indicators of compromise (IOCs). "
        "Determine the threat type, severity, and recommended mitigations. "
        "Return human-friendly analysis and a JSON block with keys: "
        "iocs, threat_type, severity, summary, recommended_actions."
    )

    # ---- Step 5: Stream response from Groq ----
    try:
        completion = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": full_input},
            ],
            temperature=0.0,
            top_p=0.95,
            max_tokens=1024,
            stream=True,
        )
    except AttributeError:
        # fallback for older SDKs
        completion = client.completions.create(
            model=model,
            prompt=f"{system_prompt}\n\nUser input:\n{full_input}",
            max_tokens=1024,
            stream=True,
        )

    accumulated = ""
    for chunk in completion:
        try:
            content = chunk.choices[0].delta.content
        except Exception:
            content = (
                chunk.get("choices", [{}])[0]
                .get("delta", {})
                .get("content", "")
                if isinstance(chunk, dict)
                else ""
            )
        if content:
            accumulated += content
            yield accumulated

# ------------------- STREAMLIT INTERFACE -------------------
st.title("🧠 AI-Powered Mail & URL Threat Detection Engine")

# Sidebar
with st.sidebar:
    st.header("⚙️ Control Panel")
    model_choice = st.selectbox(
        "Choose a model:",
        options=available_models,
        index=0,
        help="Select one of the models available to your Groq account.",
    )
    st.markdown("---")
    st.write("**Instructions:**")
    st.write(
        """
        1. Paste suspicious email or log snippet.  
        2. Click 'Analyze Threat' to get real-time threat detection.  
        3. Review structured output and indicators.
        """
    )

# Input section
st.markdown("### 📝 Input Section")
user_input = st.text_area(
    "Paste an email, suspicious text, or log snippet here:",
    height=180,
    placeholder="Enter text for analysis...",
)

if len(user_input) > 5000:
    st.warning(
        f"⚠️ Your input is {len(user_input)} characters long. "
        "Only the first and last parts will be analyzed due to model limits."
    )

# Analyze button & layout
analyze_col, info_col = st.columns([1, 2])
with analyze_col:
    analyze_clicked = st.button("🚀 Analyze Threat")
with info_col:
    st.empty()

if analyze_clicked:
    if not user_input.strip():
        st.warning("Please enter text before analysis.")
    else:
        st.info(f"Analyzing using model **{model_choice}** ...")
        placeholder = st.empty()
        final_output = ""

        with st.spinner("Running threat detection..."):
            for partial in analyze_threats_stream(user_input, model=model_choice):
                placeholder.code(partial, language="text")
                final_output = partial

        st.markdown("### ✅ Final Threat Analysis")
        st.text_area("Analysis Output", final_output, height=220)

        # Attempt to parse JSON result
        json_result = None
        try:
            start = final_output.find("{")
            end = final_output.rfind("}") + 1
            if start != -1 and end != -1 and end > start:
                json_candidate = final_output[start:end]
                json_result = json.loads(json_candidate)
        except Exception:
            json_result = None

        if json_result:
            st.markdown("### 📊 Structured Output")
            st.json(json_result)
        else:
            st.info("No structured JSON found. Re-prompt the model for explicit JSON if needed.")

# ------------------- Simulated Threat Dashboard -------------------
st.markdown("---")
st.markdown("### 📡 Real-Time Threat Intelligence Dashboard")
col1, col2 = st.columns([2, 1])

with col1:
    data = pd.DataFrame({
        "IP Address": ["192.168.1.1", "203.0.113.45", "172.16.0.5", "45.67.89.12"],
        "Threat Level": ["Low", "High", "Medium", "Critical"],
        "Detected At": pd.to_datetime(["2025-03-24 12:00", "2025-03-24 12:15", "2025-03-24 12:30", "2025-03-24 12:45"])
    })
    st.dataframe(data, use_container_width=True)

with col2:
    st.markdown("### 📈 Threat Level Distribution")
    st.bar_chart(data["Threat Level"].value_counts())

st.markdown("### 🛡️ Notes")
st.info(
    "This dashboard shows simulated real-time threat intelligence for demo purposes. "
    "All features of threat detection remain fully functional."
)
