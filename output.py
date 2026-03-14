import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os

# Page configuration
st.set_page_config(page_title="CERT Insider Threat Dashboard", layout="wide")

st.title("🚨 CERT Insider Threat Detection Dashboard")

# Load data
file_path = "processed_outputs/suspicious_users.csv"

if not os.path.exists(file_path):
    st.error("CSV file not found.")
    st.stop()

data = pd.read_csv(file_path)
data.columns = data.columns.str.strip()

# Split users
normal_users = data[data["anomaly"] == 1]
suspicious_users = data[data["anomaly"] == -1]

# Show table
st.header("🚨 Suspicious Users Table")

with st.expander("View Full Table"):
    st.dataframe(
        data,
        width="stretch"
    )
# -----------------------------
# file access vs usb 
# -----------------------------

col1, col2, col3 = st.columns([1,2,1])

with col2:

    st.subheader("📊 File Access vs USB Usage")

    fig, ax = plt.subplots(figsize=(5.2,3.6), dpi=120)

    ax.scatter(
        normal_users["file_access"],
        normal_users["usb_usage"],
        color="blue",
        s=35,
        alpha=0.7,
        label="Normal User"
    )

    ax.scatter(
        suspicious_users["file_access"],
        suspicious_users["usb_usage"],
        color="#FFB347",
        s=55,
        alpha=0.9,
        label="Suspicious User"
    )

    ax.set_title("Insider Threat Detection")
    ax.set_xlabel("File Access")
    ax.set_ylabel("USB Usage")
    ax.legend()

    st.pyplot(fig, width="content")

# -----------------------------
# risk vs threat analysis
# -----------------------------

col1, col2, col3 = st.columns([1,2,1])

with col2:

    st.subheader("📊 Risk vs Threat Analysis")

    fig, ax = plt.subplots(figsize=(5.2,3.6), dpi=120)

    ax.scatter(
        normal_users["risk_factor"],
        normal_users["threat_percentage"],
        color="blue",
        s=35,
        alpha=0.7,
        label="Normal User"
    )

    ax.scatter(
        suspicious_users["risk_factor"],
        suspicious_users["threat_percentage"],
        color="#FFB347",
        s=55,
        alpha=0.9,
        label="Suspicious User"
    )

    ax.set_title("Risk vs Threat Analysis")
    ax.set_xlabel("Risk Factor")
    ax.set_ylabel("Threat Percentage")
    ax.legend()

    st.pyplot(fig, width="content")

# -----------------------------
# anomaly factors
# -----------------------------

col1, col2, col3 = st.columns([1,2,1])

with col2:

    st.subheader("📊 Anomaly vs Risk Factor")

    fig, ax = plt.subplots(figsize=(5.2,3.6), dpi=120)

    ax.scatter(
        normal_users["risk_factor"],
        normal_users["anomaly"],
        color="blue",
        s=35,
        alpha=0.7,
        label="Normal User"
    )

    ax.scatter(
        suspicious_users["risk_factor"],
        suspicious_users["anomaly"],
        color="#FFB347",
        s=55,
        alpha=0.9,
        label="Suspicious User"
    )

    ax.set_title("Anomaly vs Risk Factor")
    ax.set_xlabel("Risk Factor")
    ax.set_ylabel("Anomaly Label")
    ax.legend()

    st.pyplot(fig, width="content")

# -----------------------------
# Risk Distribution
# -----------------------------

col1, col2, col3 = st.columns([1,2,1])

with col2:

    st.subheader("📊 Risk Factor Distribution (Suspicious Users)")

    fig, ax = plt.subplots(figsize=(5.2,3.6), dpi=120)

    ax.hist(
        suspicious_users["risk_factor"],
        bins=20,
        color="#FFB347"
    )

    ax.set_xlabel("Risk Factor")
    ax.set_ylabel("User Count")

    st.pyplot(fig, width="content")

# -----------------------------
# Night Activity vs Risk
# -----------------------------

col1, col2, col3 = st.columns([1,2,1])

with col2:

    st.subheader("📊 Night Activity vs Risk Factor (Suspicious Users)")

    fig, ax = plt.subplots(figsize=(5.2,3.6), dpi=120)

    ax.scatter(
        suspicious_users["night_activity"],
        suspicious_users["risk_factor"],
        color="#FFB347",
        s=60,
        alpha=0.9
    )

    ax.set_xlabel("Night Activity")
    ax.set_ylabel("Risk Factor")

    st.pyplot(fig, width="content")
# -----------------------------
# Top Risk Users
# -----------------------------

col1, col2, col3 = st.columns([1,2,1])

with col2:

    st.subheader("📊 Top 10 High Risk Suspicious Users")

    top_users = suspicious_users.sort_values(
        "risk_factor",
        ascending=False
    ).head(10)

    fig, ax = plt.subplots(figsize=(5.2,3.6), dpi=120)

    ax.bar(
        top_users.index.astype(str),
        top_users["risk_factor"],
        color="#FFB347"
    )

    ax.set_xlabel("User Index")
    ax.set_ylabel("Risk Factor")

    st.pyplot(fig, width="content")
   