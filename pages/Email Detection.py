import logging
import streamlit as st
import pandas as pd
import time
import email
from email import policy
from utils.predictor import predict_email
from utils.styles import load_custom_font

st.set_page_config(
    page_title="Email Detection", 
    page_icon="Email", 
    layout="centered",
    initial_sidebar_state="auto",
    menu_items={
        'About': "AI-based phishing detection system using machine learning for email classification and multi-layered URL threat analysis with 15+ security checks."
    })

load_custom_font()

# Custom CSS
st.markdown("""
    <style>
    .phishing-alert {
        background-color: #ff4444;
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 10px!important;
        text-align: center;
        animation: pulse 2s infinite;
    }
    .safe-alert {
        background-color: #00C851;
        padding: 2rem;
        margin-bottom: 10px!important;
        border-radius: 10px;
        text-align: center;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.7; }
        100% { opacity: 1; }
    }
    .confidence-meter {
        background: #f0f0f0;
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
    }
    </style>
""", unsafe_allow_html=True)

st.title("Email Phishing Detection")
st.markdown("Analyze email content to detect potential phishing attempts using AI.")

# Detection method indicator
#st.info("**Detection Method:** Machine Learning Model Only (no API option available)")

# Helper: render the shared email result panel
def _render_email_result(is_spam, displayed_label, email_body, subject, sender_email):
    st.markdown("---")
    st.markdown("## Analysis Results")

    if is_spam:
        st.markdown("""
            <h4 class="phishing-alert">
                    Phishing Detected
                </h4>
        """, unsafe_allow_html=True)
        st.error("This email shows strong indicators of being a phishing attempt!")
        st.markdown(f"**Label:** {displayed_label}")
    else:
        st.markdown("""
            <h4 class="safe-alert">
                Email Appears Safe
            </h4>
        """, unsafe_allow_html=True)
        st.success("This email appears to be legitimate.")
        st.markdown(f"**Label:** {displayed_label}")

    st.markdown("\n")
    st.markdown("### Detailed Analysis")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Risk Indicators Found")
        indicators = []

        body_lower = email_body.lower()
        if "click here" in body_lower:
            indicators.append("Suspicious call-to-action phrases")
        if "verify" in body_lower or "confirm" in body_lower:
            indicators.append("Urgency/verification requests")
        if "http://" in email_body:
            indicators.append("Non-secure HTTP links detected")
        if any(word in body_lower for word in ["urgent", "immediately", "act now"]):
            indicators.append("Urgency language detected")
        if any(word in body_lower for word in ["password", "credit card", "ssn", "bank account"]):
            indicators.append("Sensitive information request")

        if indicators:
            for indicator in indicators:
                st.markdown(f"- {indicator}")
        else:
            st.markdown("No major risk indicators found")

    with col2:
        st.markdown("#### Email Features")
        features_df = pd.DataFrame({
            'Feature': ['Sender Domain', 'Subject Line', 'URL Count'],
            'Status': [
                sender_email.split('@')[1] if '@' in sender_email else 'N/A',
                subject if subject else 'No subject',
                str(email_body.count('http'))
            ]
        })
        st.dataframe(features_df, use_container_width=True, hide_index=True)

    st.markdown("### Recommendations")
    if is_spam:
        st.warning("""
        **What to do:**
        - Do NOT click any links in this email
        - Do NOT reply or provide any information
        - Delete this email immediately
        - Report to your email provider as phishing
        - If you clicked any links, change your passwords immediately
        """)
    else:
        st.info("""
        **Safety Tips:**
        - Email appears legitimate, but always stay vigilant
        - Verify sender's email address matches official domains
        - Hover over links before clicking to check destinations
        - When in doubt, contact the organization directly
        """)


def _interpret_email_label(model_label):
    """
    Interpret the model's label output as spam or not spam.
    
    Email models return binary classification:
    - 0 or '0' = Non-spam/Ham (legitimate email)
    - 1 or '1' = Spam (phishing/malicious email)
    """
    # Handle None or empty string edge cases
    if model_label is None or (isinstance(model_label, str) and not model_label.strip()):
        return False, 'Unknown'
    
    # Normalize to string and lowercase for comparison
    normalized = str(model_label).strip().lower()
    
    # Check for spam indicators
    if normalized in ('1', 'spam', 'spammy'):
        return True, 'Spam'
    
    # Check for non-spam indicators  
    if normalized in ('0', 'ham', 'real', 'non-spam', 'legitimate'):
        return False, 'Real'
    
    # Fallback for unexpected values
    logging.warning(f"Unexpected email label value: {model_label} (normalized: {normalized})")
    return False, 'Unknown'

# Tabs for different input methods
tab1, tab2, tab3 = st.tabs(["Paste Email Content", "Upload Email File", "Batch Analysis"])

with tab1:
    st.markdown("### Enter Email Details")
    
    subject = st.text_input("Email Subject", placeholder="Enter email subject")
    sender_email = ''
    
    email_body = st.text_area(
        "Email Body",
        height=300,
        placeholder="""Paste the full email content here...

Example:
Dear Customer,

Your account has been compromised. Click here immediately to verify your identity:
http://suspicious-link.com

Thank you,
Security Team"""
    )
    
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        analyze_btn = st.button("Analyze Email", type="primary", use_container_width=True)
    with col2:
        clear_btn = st.button("Clear", use_container_width=True)
    
    if clear_btn:
        st.rerun()
    
    if analyze_btn:
        if not email_body or not email_body.strip():
            st.error("Email body is required for analysis")
        else:
            with st.spinner("Analyzing email..."):
                
                displayed_label = 'Unknown'
                is_spam = False
                try:
                    result = predict_email(subject, email_body)
                    model_label = result.get('label', '')
                    confidence = float(result.get('confidence', 0.0))
                    is_spam, displayed_label = _interpret_email_label(model_label)
                except FileNotFoundError:
                    logging.exception("Email model is missing")
                    st.error("Email model not found. Please check that the model is downloaded and configured correctly.")
                    st.stop()
                except Exception as err:
                    logging.exception("Email model prediction failed")
                    st.error(f"Email prediction failed ({err}).")
                    st.stop()
                
                _render_email_result(is_spam, displayed_label, email_body, subject, sender_email)

with tab2:
    st.markdown("### Upload Email File")
    st.info("Upload .eml, .msg, or .txt files containing email content")
    
    uploaded_file = st.file_uploader(
        "Choose an email file",
        type=['eml', 'msg', 'txt'],
        help="Supported formats: .eml, .msg, .txt"
    )
    
    if uploaded_file:
        raw_bytes = uploaded_file.read()
        st.success(f"File uploaded: {uploaded_file.name}")

        file_details = {
            "Filename": uploaded_file.name,
            "File Size": f"{len(raw_bytes) / 1024:.2f} KB",
            "File Type": uploaded_file.type or 'N/A'
        }
        st.json(file_details)

        subject_from_file = ''
        body_from_file = ''
        file_lower = uploaded_file.name.lower()

        if file_lower.endswith('.eml'):
            try:
                msg = email.message_from_bytes(raw_bytes, policy=policy.default)
                subject_from_file = msg.get('subject', '') or ''
                body_from_file = ''
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == 'text/plain' and not part.get_content_disposition():
                            body_from_file = part.get_content()
                            break
                else:
                    body_from_file = msg.get_content()

                if not body_from_file and msg.get_body(preferencelist=('plain', 'html')):
                    body_from_file = msg.get_body(preferencelist=('plain', 'html')).get_content()
            except Exception:
                logging.exception("Failed to parse uploaded .eml file")
                body_from_file = ''
        else:
            try:
                body_from_file = raw_bytes.decode('utf-8')
            except UnicodeDecodeError:
                body_from_file = raw_bytes.decode('latin1', errors='ignore')

        subject_input = st.text_input("Email Subject", value=subject_from_file)
        body_input = st.text_area("Email Body", value=body_from_file, height=300)

        if st.button("Analyze Uploaded Email", type="primary"):
            if not body_input or not body_input.strip():
                st.error("Uploaded email must include a body to analyze.")
            else:
                with st.spinner("Analyzing uploaded email..."):
                    try:
                        result = predict_email(subject_input, body_input)
                        model_label = result.get('label', '')
                        confidence = float(result.get('confidence', 0.0))
                        is_spam, displayed_label = _interpret_email_label(model_label)
                    except FileNotFoundError:
                        logging.exception("Email model is missing")
                        st.error("Email model not found. Please configure the model before uploading emails.")
                        st.stop()
                    except Exception as err:
                        logging.exception("Uploaded email prediction failed")
                        st.error(f"Email prediction failed ({err}).")
                        st.stop()

                _render_email_result(is_spam, displayed_label, body_input, subject_input, '')

with tab3:
    st.markdown("### Batch Email Analysis")
    st.info("Upload a CSV file with subject and body text for bulk scoring. Sender metadata is not required.")
    
    st.markdown("""
    **CSV Format Required:**
    - Column 1: `subject`
    - Column 2: `body`
    """)
    
    sample_data = pd.DataFrame({
        'subject': [
            'Meeting Reminder: Project Sync at 2PM',
            'Your Receipt for Laptop Purchase',
            'URGENT: Your Account Has Been Suspended!!!',
            'You Won $500,000 Lottery!!!'
        ],
        'body': [
            '''Hi John,

Just a reminder about our project sync meeting scheduled for today at 2PM.

We will discuss the current sprint progress and blockers.

Regards,
Aisha''',
            '''Dear Customer,

Thank you for your recent purchase. Please find your receipt attached.

Order ID: TS-44521

Support Team
TechStore''',
            '''Dear User,

Your account has been suspended due to suspicious activity.
Click the link below to verify immediately or your account will be deleted:

http://fake-paypal-login.example.invalid

Act now!''',
            '''Congratulations!!!

You have been selected as a winner in our international lottery.
Send your bank details and ID to claim your prize now.

Do not miss this opportunity!'''
        ]
    })
    
    st.download_button(
        label="Download Sample CSV",
        data=sample_data.to_csv(index=False),
        file_name="sample_emails.csv",
        mime="text/csv"
    )
    
    batch_file = st.file_uploader("Upload CSV file", type=['csv'])
    
    if batch_file:
        # Use utf-8-sig encoding to handle BOM characters
        df = pd.read_csv(batch_file, encoding='utf-8-sig')
        columns_lower = {col.lower(): col for col in df.columns}
        if 'subject' not in columns_lower or 'body' not in columns_lower:
            st.error("CSV must include both `subject` and `body` columns.")
            st.stop()

        df = df.rename(columns={
            columns_lower['subject']: 'subject',
            columns_lower['body']: 'body'
        })

        st.dataframe(df.head(), use_container_width=True)

        if st.button("Analyze All Emails", type="primary"):
            total = len(df)
            progress_bar = st.progress(0)
            status_text = st.empty()

            results = []

            for i, row in df.iterrows():
                progress_bar.progress((i + 1) / total)
                status_text.text(f"Analyzing email {i + 1} of {total}...")
                time.sleep(0.1)

                subject_raw = row['subject']
                body_raw = row['body']
                subject = '' if pd.isna(subject_raw) else str(subject_raw)
                body = '' if pd.isna(body_raw) else str(body_raw)

                if not body.strip():
                    results.append({
                        'Subject': subject if subject else 'No subject',
                        'Label': 'Missing body',
                        # 'Confidence': '0.0%',
                        'Spam': 'Unknown'
                    })
                    continue

                try:
                    prediction = predict_email(subject, body)
                except FileNotFoundError:
                    logging.exception("Email model missing during batch run")
                    st.error("Email model not found. Please configure it before running batch analysis.")
                    st.stop()
                except Exception as err:
                    logging.exception("Batch email prediction failed")
                    st.error(f"Bulk prediction failed ({err}).")
                    st.stop()

                model_label = prediction.get('label', '')
                confidence = float(prediction.get('confidence', 0.0))
                _, label_display = _interpret_email_label(model_label)

                results.append({
                    'Subject': subject if subject else 'No subject',
                    'Label': label_display,
                    # 'Confidence': f"{confidence * 100:.1f}%",
                    'Spam': 'Yes' if label_display == 'Spam' else 'No'
                })

            st.success(f"Analyzed {total} emails successfully!")

            results_df = pd.DataFrame(results)
            st.dataframe(results_df, use_container_width=True, hide_index=True)

            phishing_count = sum(1 for r in results if r.get('Label') == 'Spam')
            safe_count = len(results) - phishing_count

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Emails", total)
            with col2:
                st.metric("Phishing Detected", phishing_count)
            with col3:
                st.metric("Safe Emails", safe_count)


# Sidebar info
# with st.sidebar:
#     st.markdown("### Common Phishing Signs")
#     st.markdown("""
#     - Spelling and grammar errors
#     - Urgent or threatening language
#     - Requests for personal information
#     - Suspicious links or attachments
#     - Mismatched sender addresses
#     - Too-good-to-be-true offers
#     """)
