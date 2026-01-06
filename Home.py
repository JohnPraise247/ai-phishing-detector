import streamlit as st
import pandas as pd
from datetime import datetime
from utils.styles import load_custom_font

# Page configuration
st.set_page_config(
    page_title="AI Phishing Detector",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="auto",
    menu_items={
        'About': "This application uses AI to detect phishing emails and URLs."
    }
)

load_custom_font()

# Custom CSS
st.markdown("""
    <style>
    .medium-opacity{
        opacity: 0.5;
    }
    .metric-card {
        background: #1c1c1c;
        padding: 1.5rem;
        border-radius: 10px;
        text-align: center;
    }

    .sub-headerx {
        text-align: center;
        color: #555;
        font-size: 1.2rem;
        margin-bottom: 2rem;
    }
    
    .feature-box {
        background: #1c1c1c;
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid #494949;
        margin: 1rem 0;
    }
    </style>
""", unsafe_allow_html=True)


# Main content
st.markdown('<h1>AI-Based Phishing Email and Website Detection System Using Machine Learning</h1>', unsafe_allow_html=True)
# st.markdown('<p>Protecting You from Phishing Attacks Using Machine Learning.</p>', unsafe_allow_html=True)

st.markdown("""
#### About this project
We combine a pretrained email classifier with a trusted URL reputation check so every submission (single or batch) gets a hardened ML/API verdict plus risk indicators and recommendations.
""", unsafe_allow_html=True)

# Hero section
# col1, col2, col3 = st.columns(3)

# with col1:
#     st.markdown("""
#     <div class="metric-card">
#         <h2>98.5%</h2>
#         <p>Detection Accuracy</p>
#     </div>
#     """, unsafe_allow_html=True)

# with col2:
#     st.markdown("""
#     <div class="metric-card">
#         <h2>50K+</h2>
#         <p>Emails Analyzed</p>
#     </div>
#     """, unsafe_allow_html=True)

# with col3:
#     st.markdown("""
#     <div class="metric-card">
#         <h2>&lt;2s</h2>
#         <p>Average Detection Time</p>
#     </div>
#     """, unsafe_allow_html=True)

# st.markdown("<br>", unsafe_allow_html=True)

# Introduction
# st.markdown("#### What is Phishing?")
# st.markdown("""
# Phishing is a cybercrime where attackers impersonate legitimate organizations to steal sensitive 
# information such as passwords, credit card numbers, and personal data. Our AI-powered system 
# helps identify and prevent these malicious attempts before they cause harm.
# """)

# st.markdown("<br>", unsafe_allow_html=True)

# Key Features
st.markdown("#### Key Features")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    <div class="feature-box">
        <h5>Email Model</h5>
        <p>Subject/body content is scored by the pretrained email classifier.</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="feature-box">
        <h5>Live Prediction</h5>
        <p>The UI makes the Safe Browsing or email call directly—no heuristics.</p>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="feature-box">
        <h5>URL Safety</h5>
        <p>Each URL is vetted by an external reputation service.</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="feature-box">
        <h5>Detailed Reports</h5>
        <p>Risk indicators and recommendations are surfaced.</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# st.markdown("#### How It Works")

# st.markdown("##### 1. Input")
# st.write("Submit an email or URL for analysis")

# st.divider()

# st.markdown("##### 2. Process")
# st.write("AI extracts features and patterns")
# st.divider()

# st.markdown("##### 3. Analyze")
# st.write("ML models predict phishing probability")
# st.divider()

# st.markdown("##### 4. Results")
# st.write("Get detailed detection report")
# st.divider()


# Call to action


# st.markdown("#### Pages")
# st.page_link(
#     "Home.py",
#     label="Home",
# )

# st.page_link(
#     "pages/Email Detection.py",
#     label="Email Detection",
# )

# st.page_link(
#     "pages/URL Detection.py",
#     label="URL Detection",
# )