import streamlit as st
import pandas as pd
import time
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

import logging

from utils.styles import load_custom_font
from utils.predictor import predict_url, predict_urls, probe_url

def _normalize_host(raw_input: str) -> str:
    cleaned = raw_input.strip()
    cleaned = re.sub(r'^(https?://)', '', cleaned, flags=re.IGNORECASE)
    return cleaned


def _extract_urls_from_text(text: str) -> list[str]:
    """
    Extract all valid URLs from pasted text.
    Handles URLs separated by newlines, spaces, or commas.
    Returns a list of URLs found in the text.
    """
    if not text or not text.strip():
        return []
    
    # Split by newlines, spaces, or commas
    # First, normalize line endings and split by newlines
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    
    urls = []
    for line in lines:
        # Further split by spaces and commas
        parts = re.split(r'[\s,]+', line)
        for part in parts:
            part = part.strip().strip('"\'')
            # Check if this looks like a URL
            if part.startswith(('http://', 'https://')):
                urls.append(part)
            elif '.' in part and len(part) > 3:
                # Could be a domain without scheme - check if it looks like a domain
                # e.g., "example.com" or "example.com/path"
                if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}', part):
                    urls.append(f'https://{part}')
    
    return urls

def _normalize_host_input():
    st.session_state["website_url"] = _normalize_host(st.session_state.get("website_url", ""))

def _has_valid_domain(netloc: str) -> bool:
    host = netloc.split(':')[0].strip().lower()
    if not host:
        return False
    if host in {'localhost', '127.0.0.1'}:
        return True
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
        return True
    if '.' not in host:
        return False
    parts = [part for part in host.split('.') if part]
    if len(parts) < 2:
        return False
    return all(re.match(r'^[a-zA-Z0-9-]+$', part) for part in parts)

KNOWN_BRANDS = [
    "google",
    "facebook",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
    "twitter",
    "paypal",
    "linkedin",
    "dropbox",
    "github",
    "spotify",
    "adobe",
    "ebay",
    "airbnb",
    "uber",
    "slack",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
    ".cc", ".su", ".buzz", ".work", ".click", ".link", ".info",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "short.link", "t.co",
    "is.gd", "buff.ly", "adf.ly", "bit.do", "lnkd.in", "shorte.st",
    "rb.gy", "cutt.ly", "tiny.cc", "shorturl.at", "s.id",
}

# Homograph confusables: maps lookalike chars to their ASCII equivalents
HOMOGRAPH_MAP = {
    '0': 'o', 'о': 'o', 'ο': 'o',  # Cyrillic/Greek о, digit 0
    '1': 'l', 'і': 'i', 'ι': 'i', 'l': 'l', '|': 'l',  # digit 1, Cyrillic/Greek i
    '3': 'e', 'е': 'e', 'ε': 'e',  # digit 3, Cyrillic е
    '4': 'a', 'а': 'a', 'α': 'a',  # Cyrillic/Greek a
    '5': 's', 'ѕ': 's',  # Cyrillic s
    '8': 'b',
    '@': 'a',
    '$': 's',
    'ç': 'c', 'с': 'c',  # Cyrillic с
    'ń': 'n', 'п': 'n',
    'ú': 'u', 'υ': 'u', 'ц': 'u',
    'ý': 'y', 'у': 'y',
    'х': 'x',
    'р': 'p',  # Cyrillic р
    'ω': 'w',
    'ν': 'v',
    'κ': 'k', 'к': 'k',
    'τ': 't', 'т': 't',
    'м': 'm',
}


def _normalize_homoglyphs(text: str) -> str:
    return ''.join(HOMOGRAPH_MAP.get(ch, ch) for ch in text.lower())


def _detect_typosquatting(netloc: str) -> tuple[str | None, float | None]:
    host = netloc.split(':')[0].lower()
    primary_label = host.split('.')[-2] if len(host.split('.')) > 1 else host
    normalized_label = _normalize_homoglyphs(primary_label)
    best_brand = None
    best_ratio = 0.0

    for brand in KNOWN_BRANDS:
        # Compare both raw and homoglyph-normalized versions
        ratio_raw = SequenceMatcher(None, primary_label, brand).ratio()
        ratio_normalized = SequenceMatcher(None, normalized_label, brand).ratio()
        ratio = max(ratio_raw, ratio_normalized)
        if ratio > best_ratio:
            best_ratio = ratio
            best_brand = brand

    if best_brand and best_ratio >= 0.8 and primary_label != best_brand:
        return best_brand, best_ratio
    return None, None


def _detect_homograph_attack(netloc: str) -> bool:
    host = netloc.split(':')[0]
    # Check for non-ASCII characters (potential homograph/IDN attack)
    try:
        host.encode('ascii')
        return False
    except UnicodeEncodeError:
        return True


def _check_suspicious_tld(netloc: str) -> str | None:
    host = netloc.split(':')[0].lower()
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return tld
    return None


def _check_excessive_dashes_numbers(netloc: str) -> tuple[bool, bool]:
    host = netloc.split(':')[0].lower()
    # Remove TLD for analysis
    parts = host.rsplit('.', 1)
    domain_part = parts[0] if parts else host

    dash_count = domain_part.count('-')
    digit_count = sum(1 for c in domain_part if c.isdigit())
    alpha_count = sum(1 for c in domain_part if c.isalpha())

    excessive_dashes = dash_count >= 3
    excessive_numbers = alpha_count > 0 and digit_count / max(alpha_count, 1) > 0.5

    return excessive_dashes, excessive_numbers


def _is_url_shortener(netloc: str) -> bool:
    host = netloc.split(':')[0].lower()
    return host in URL_SHORTENERS or host.startswith('www.') and host[4:] in URL_SHORTENERS


def _has_non_standard_port(netloc: str) -> int | None:
    if ':' in netloc:
        try:
            port = int(netloc.split(':')[1])
            # Standard ports: 80 (HTTP), 443 (HTTPS), 8080 (alt HTTP), 8443 (alt HTTPS)
            if port not in {80, 443, 8080, 8443}:
                return port
        except (ValueError, IndexError):
            pass
    return None


def _compute_risk_indicators(parsed, url_input):
    risk_indicators = []
    risk_score = 0
    host = parsed.netloc.split(':')[0].lower()
    is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host))

    if parsed.scheme == 'http':
        risk_indicators.append("No SSL/TLS encryption")
        risk_score += 30

    suspicious_keywords = ['verify', 'account', 'login', 'secure', 'update', 'confirm']
    if any(keyword in url_input.lower() for keyword in suspicious_keywords):
        risk_indicators.append("Suspicious keywords in URL")
        risk_score += 25

    if len(parsed.path) > 50:
        risk_indicators.append("Unusually long URL path")
        risk_score += 15

    if not is_ip and parsed.netloc.count('.') > 2:
        risk_indicators.append("Multiple subdomains")
        risk_score += 20

    if '@' in url_input:
        risk_indicators.append("Contains @ symbol (phishing technique)")
        risk_score += 35

    if len(parsed.netloc) > 30:
        risk_indicators.append("Unusually long domain name")
        risk_score += 10

    # Full URL length check (stricter threshold)
    if len(url_input) > 75:
        risk_indicators.append(f"Suspiciously long URL ({len(url_input)} characters)")
        risk_score += 20

    # URL shortener check
    if _is_url_shortener(parsed.netloc):
        risk_indicators.append("URL shortener detected (hides final destination)")
        risk_score += 30

    # Non-standard port check
    non_standard_port = _has_non_standard_port(parsed.netloc)
    if non_standard_port:
        risk_indicators.append(f"Non-standard port: {non_standard_port}")
        risk_score += 25

    # Double slashes in path
    if '//' in parsed.path:
        risk_indicators.append("Double slashes in URL path (path manipulation)")
        risk_score += 20

    # IP address instead of domain
    if is_ip:
        risk_indicators.append("Using IP address instead of domain name")
        risk_score += 25

    # Suspicious TLD check
    suspicious_tld = _check_suspicious_tld(parsed.netloc)
    if suspicious_tld:
        risk_indicators.append(f"Suspicious TLD: {suspicious_tld}")
        risk_score += 25

    # Homograph/IDN attack check
    if not is_ip and _detect_homograph_attack(parsed.netloc):
        risk_indicators.append("Homograph attack: contains non-ASCII lookalike characters")
        risk_score += 40

    # Excessive dashes/numbers check
    if not is_ip:
        excessive_dashes, excessive_numbers = _check_excessive_dashes_numbers(parsed.netloc)
        if excessive_dashes:
            risk_indicators.append("Excessive dashes in domain name")
            risk_score += 15
        if excessive_numbers:
            risk_indicators.append("Excessive numbers in domain name")
            risk_score += 15

    # Typosquatting / brand impersonation check
    brand, similarity = _detect_typosquatting(parsed.netloc)
    if brand:
        risk_indicators.append(
            f"Typosquatting candidate: similar to {brand.title()} ({similarity:.2f} similarity)"
        )
        risk_score += 30

    return risk_indicators, risk_score

def _is_benign_label(label: str) -> bool:
    """
    Check if a label indicates a benign/safe URL.
    Handles both semantic ('benign') and numeric ('0') labels for robustness.
    Numeric labels should be converted by predictor.py, but we handle them here as fallback.
    """
    return label.lower() in ('benign', '0')

def _get_model_label_display(model_label: str) -> str:
    """Map model/API labels to user-friendly display names.
    
    Handles labels from both:
    - ML Model: benign, defacement, phishing, malware (and numeric 0-3)
    - Safe Browsing API: benign, malware, social_engineering, unwanted_software, etc.
    """
    # Check numeric labels before lowercasing (since '0'.lower() == '0')
    numeric_label_map = {
        '0': 'Benign (Safe)',
        '1': 'Defacement (Hacked)',
        '2': 'Phishing (Danger)',
        '3': 'Malware (Virus)'
    }
    
    if model_label in numeric_label_map:
        # Log when numeric fallback is used (indicates predictor.py conversion may have failed)
        logging.warning(f"Numeric label '{model_label}' encountered in display function. "
                       "Expected semantic label from predictor.py.")
        return numeric_label_map[model_label]
    
    # Handle semantic labels from both ML model and Safe Browsing API
    semantic_label_map = {
        # ML Model labels
        'defacement': 'Defacement (Hacked)',
        'benign': 'Benign (Safe)',
        'phishing': 'Phishing (Danger)',
        'malware': 'Malware (Virus)',
        # Safe Browsing API labels
        'social_engineering': 'Phishing (Social Engineering)',
        'unwanted_software': 'Unwanted Software',
        'potentially_harmful_application': 'Potentially Harmful App',
        # Additional statuses
        'unreachable': 'Unreachable',
        'unknown': 'Unknown',
        'suspicious': 'Suspicious',
    }
    
    return semantic_label_map.get(model_label.lower(), model_label.replace('_', ' ').title())

def _derive_status(model_label: str, reachability: dict, risk_score: int, redirect_count: int, use_model: bool = False) -> tuple[str, str]:
    # Determine final host (if available) so we can apply whitelisting
    final_url = reachability.get('final_url') or ''
    final_host = ''
    try:
        final_host = urlparse(final_url).netloc.split(':')[0].lower() if final_url else ''
    except Exception:
        final_host = ''

    # Whitelist suffixes (hosts under these suffixes will not be auto-flagged
    # solely because of redirect chains). Add other trusted hosting providers
    # here as needed.
    WHITELIST_SUFFIXES = ('streamlit.app',)
    whitelisted = any(final_host.endswith(suffix) for suffix in WHITELIST_SUFFIXES if final_host)

    if not reachability.get('reachable'):
        return "Suspicious", "Host is unreachable and could be down, so we cannot confirm it as safe."
    
    # Check if label indicates safe/benign
    if not _is_benign_label(model_label):
        # Only show Safe Browsing message when not in model mode
        if use_model:
            label_display = _get_model_label_display(model_label)
            return "Not Safe", f"The ML model detected this URL as: {label_display}"
        else:
            return "Not Safe", "Safe Browsing reported this URL as a confirmed threat."

    # Only treat redirect chains as suspicious for non-whitelisted hosts
    if not whitelisted and (redirect_count >= 3 or reachability.get('redirect_count', 0) >= 3):
        return "Suspicious", f"Redirect chain includes {redirect_count} hops, which can hide malicious targets."

    if risk_score >= 40:
        return "Suspicious", f"Risk score {risk_score}/100 indicates suspicious characteristics."
    return "Safe", "This URL presents no obvious threats and passed the reachability check."

st.set_page_config(
    page_title="URL Detection", 
    page_icon="URL", 
    layout="centered",
    initial_sidebar_state="auto",
    menu_items={
        'About': "AI-based phishing detection system using machine learning for email classification and multi-layered URL threat analysis with 15+ security checks."
    })

load_custom_font()


# Custom CSS
st.markdown("""
    <style>
    .url-safe {
        background: linear-gradient(135deg, #00C851 0%, #007E33 100%);
        padding: 2rem;
        margin-bottom: 10px!important;
        border-radius: 15px;
        text-align: center;
    }
    .url-phishing {
        background: #cc0000;/*#ff4444;*/
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 10px!important;
        text-align: center;
        animation: shake 0.5s;
    }
    .url-phishing.warn {
        background: #cc5400;
        color: black;
    }
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-10px); }
        75% { transform: translateX(10px); }
    }
    .feature-card {
        background: #141414;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
    }
    .feature-card.warn {
        background: #3d3d0e;
    }
    .risk-progress {
        background: #1f1f1f;
        border-radius: 6px;
        overflow: hidden;
        height: 7px;
    }
    .risk-progress > div {
        height: 100%;
        background: linear-gradient(135deg, #ffb347 0%, #ffcc33 100%)!important;
        border-radius: 6px;
    }
    </style>
""", unsafe_allow_html=True)

st.title("URL Phishing Detection")
st.markdown("Check if a website is safe to visit using live reputation scoring from the URL service.")

# Detection mode selector
detection_mode = st.radio(
    "Detection Mode:",
    ["API (Safe Browsing)", "Model (ML-based)"],
    horizontal=True,
    help="Choose between Safe Browsing API or machine learning model for URL detection"
)
use_model = detection_mode == "Model (ML-based)"

# Main tabs
tab1, tab2 = st.tabs(["Single URL Check", "Batch URL Analysis"])


def _render_reachability_summary(reachability: dict):
    reach_status = "Reachable" if reachability.get('reachable') else "Unreachable"
    status_code = reachability.get('status_code')
    response_time = reachability.get('response_time_ms')
    final_url = reachability.get('final_url')
    redirects = reachability.get('redirects') or []
    tls_status = reachability.get('tls_valid')
    tls_text = "Valid" if tls_status else ("Invalid" if tls_status is False else "Unknown")

    reach_col1, reach_col2, reach_col3 = st.columns(3)
    with reach_col1:
        st.metric("Reachability", reach_status)
        st.metric("HTTP Status", f"{status_code}" if status_code else "N/A")
    with reach_col2:
        st.metric("Response Time", f"{response_time} ms" if response_time else "N/A")
        st.metric("TLS Status", tls_text)
    with reach_col3:
        st.metric("Final URL", final_url or "N/A")
        st.metric("Redirects", f"{len(redirects)} hops" if redirects else "0 hops")

    if reachability.get('status_message'):
        st.caption(f"Server message: {reachability.get('status_message')}")
    if redirects or final_url:
        chain = redirects + ([final_url] if final_url else [])
        st.caption(f"Redirect chain: {' ➝ '.join(chain)}")
    if reachability.get('error'):
        st.warning(f"Reachability error: {reachability.get('error')}")

with tab1:
    st.markdown("#### Enter URL to Analyze")
    
    scheme_col, url_col = st.columns([0.7, 3])
    with scheme_col:
        scheme = st.selectbox("Scheme", ["https://", "http://"], index=0, help="Select the protocol to prefix the hostname.")
    if "website_url" not in st.session_state:
        st.session_state["website_url"] = ""
    with url_col:
        st.text_input(
            "Website URL",
            placeholder="example.com",
            help="Enter the hostname without the protocol.",
            key="website_url",
            on_change=_normalize_host_input
        )
    normalized_host = st.session_state.get("website_url", "")
    url_input = f"{scheme}{normalized_host}" if normalized_host else ""
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        check_btn = st.button("Check URL", type="primary", use_container_width=True)
    with col2:
        st.button("Clear", use_container_width=True)
    
    if check_btn:
        if not url_input:
            st.error("Please enter a URL to analyze!")
        elif not url_input.startswith(('http://', 'https://')):
            st.warning("URL should start with http:// or https://")
        else:
            # Check if multiple URLs were pasted
            raw_input = st.session_state.get("website_url", "")
            extracted_urls = _extract_urls_from_text(f"{scheme}{raw_input}")
            
            if len(extracted_urls) > 1:
                st.warning(
                    f"Multiple URLs detected ({len(extracted_urls)} URLs). "
                    f"Please use the **Batch URL Analysis** tab for checking multiple URLs at once."
                )
                with st.expander("URLs detected:"):
                    for i, detected_url in enumerate(extracted_urls, 1):
                        st.code(detected_url, language=None)
                st.stop()
            
            parsed = urlparse(url_input)
            domain = parsed.netloc
            if not _has_valid_domain(domain):
                st.error("Enter a host that includes a full domain (e.g., example.com) or IP address.")
                st.stop()

            spinner = st.spinner("Analyzing URL...")
            spinner.__enter__()
            spinner_active = True
            try:
                reachability = probe_url(url_input)
                if not reachability.get('reachable'):
                    spinner.__exit__(None, None, None)
                    spinner_active = False
                    st.warning(
                        "Hostname is not reachable; ensure the domain resolves and responds before re-running the check."
                    )
                    _render_reachability_summary(reachability)
                    st.stop()

                try:
                    result = predict_url(url_input, reachability=reachability, use_model=use_model)
                    model_label = result.get('label', 'benign').lower()
                    confidence = float(result.get('confidence', 0.0))
                    reachability = result.get('reachability', reachability)
                except Exception:
                    logging.exception("URL prediction failed")
                    st.error("URL prediction failed. Please try again shortly.")
                    st.stop()
                risk_indicators, risk_score = _compute_risk_indicators(parsed, url_input)
                redirect_count = reachability.get('redirect_count', 0)
                status_label, status_reason = _derive_status(
                    model_label, reachability, risk_score, redirect_count, use_model
                )
            finally:
                if spinner_active:
                    spinner.__exit__(None, None, None)

            # Check if label indicates phishing/malicious
            is_phishing = not _is_benign_label(model_label)
            displayed_label = _get_model_label_display(model_label)

            st.markdown("---")
            st.markdown("#### URL Analysis Results")
            
            # Main result
            result_col, prediction_col = st.columns([3, 1])
            with result_col:
                if status_label == "Not Safe":
                    st.markdown("""
                        <h4 class="url-phishing">
                            Dangerous Website Detected
                        </h4>
                    """, unsafe_allow_html=True)
                    st.error("This URL shows multiple phishing indicators. Do not visit!")
                elif status_label == "Suspicious":
                    st.markdown("""
                        <h4 class="url-phishing warn">
                            Suspicious Activity Detected
                        </h4>
                    """, unsafe_allow_html=True)
                    st.warning("There are signals that warrant further verification before trusting this site.")
                else:
                    st.markdown("""
                        <h4 class="url-safe">
                            URL Appears Safe
                        </h4>
                    """, unsafe_allow_html=True)
                    st.success("This website appears to be legitimate and safe to visit.")
                st.caption(status_reason)
            with prediction_col:
                # Show the prediction label for both API and Model modes
                try:
                    st.info(f"**{displayed_label}**")
                except Exception:
                    pass
            
            # Confidence meter
            # st.markdown("#### Confidence Score")
            # confidence_col1, confidence_col2 = st.columns([3, 1])
            # with confidence_col1:
            #     st.progress(confidence)
            # with confidence_col2:
            #     st.metric("Confidence", f"{confidence * 100:.1f}%")
            
            # URL breakdown
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("#### URL Component Analysis")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("##### URL Components")
                final_destination = reachability.get('final_url')
                final_destination_value = (
                    final_destination if final_destination and final_destination != url_input else "Same as requested"
                )
                components = pd.DataFrame({
                    'Component': ['Protocol', 'Domain', 'Path', 'Full URL', 'Final Destination'],
                    'Value': [
                        parsed.scheme,
                        domain,
                        parsed.path if parsed.path else '/',
                        url_input[:50] + '...' if len(url_input) > 50 else url_input,
                        final_destination_value
                    ]
                })
                st.dataframe(components, use_container_width=True, hide_index=True)
                
                # Security features
                st.markdown("##### Security Features")
                security_features = []
                
                if parsed.scheme == 'https':
                    security_features.append("HTTPS Encryption")
                else:
                    security_features.append("No HTTPS (Insecure)")
                
                if len(domain.split('.')) <= 3:
                    security_features.append("Normal domain structure")
                else:
                    security_features.append("Multiple subdomains detected")
                
                # Check for IP address
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    security_features.append("IP address instead of domain")
                else:
                    security_features.append("Proper domain name")
                
                for feature in security_features:
                    st.markdown(f"<div class='feature-card'>{feature}</div>", unsafe_allow_html=True)
            
            with col2:
                st.markdown("##### Risk Indicators")
                if risk_indicators:
                    for indicator in risk_indicators:
                        st.markdown(f"<div class='feature-card warn'>{indicator}</div>", unsafe_allow_html=True)
                    st.markdown(f"**Total Risk Score: {risk_score}/100**")
                    pct = max(0, min(risk_score, 100))
                    st.markdown(
                        f"<div class='risk-progress'><div style='width: {pct}%;'></div></div>",
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown("<div class='feature-card'>No significant risk indicators found</div>", unsafe_allow_html=True)
                    st.markdown("**Total Risk Score: 0/100**")
                    st.markdown(
                        "<div class='risk-progress'><div style='width: 0%;'></div></div>",
                        unsafe_allow_html=True,
                    )

            # URL Features Summary
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("#### Feature Analysis Summary", unsafe_allow_html=True)
            
            feature_col1, feature_col2, feature_col3, feature_col4 = st.columns(4)
            
            with feature_col1:
                st.metric("URL Length", f"{len(url_input)} chars")
            with feature_col2:
                st.metric("Domain Length", f"{len(domain)} chars")
            with feature_col3:
                st.metric("Subdomain Count", len(domain.split('.')) - 1)
            with feature_col4:
                st.metric("Special Chars", url_input.count('-') + url_input.count('_'))
            
            # Recommendations
            st.markdown("#### Recommendations")
            
            if status_label == "Not Safe":
                st.error("""
                **Security Warning:**
                - Do not visit this website
                - Do not enter any personal information
                - Do not download anything from this site
                - Report this URL to your security team
                - Run a security scan if you visited this site
                """)
            elif status_label == "Suspicious":
                st.warning("""
                **Caution:**
                - Double-check the URL spelling and certificate
                - Avoid entering credentials until you confirm the destination
                - Consider running additional scans before proceeding
                """)
            else:
                st.info("""
                **Safety Tips:**
                - Always verify you're on the correct website
                - Check for HTTPS and valid SSL certificate
                - Look for trust indicators (padlock icon, company info)
                - Be cautious with links from emails or messages
                - Use bookmarks for frequently visited sites
                """)
            
            # Additional Info
            # with st.expander("Technical Details"):
            #     st.json({
            #         "url": url_input,
            #         "protocol": parsed.scheme,
            #         "domain": domain,
            #         "path": parsed.path,
            #         "query": parsed.query if parsed.query else "None",
            #         "has_https": parsed.scheme == "https",
            #         "subdomain_count": len(domain.split('.')) - 1,
            #         "url_length": len(url_input),
            #         "prediction": "Phishing" if is_phishing else "Safe",
            #         # "confidence": f"{confidence * 100:.2f}%"
            #     })

with tab2:
    st.markdown("### Batch URL Analysis")
    st.info("Upload a text file or CSV with multiple URLs for bulk checking")
    
    # Sample data
    st.markdown("**Expected Format:**")
    st.markdown("For text files (one URL per line):")
    st.code("https://example1.com\nhttps://example2.com\nhttps://example3.com", language="text")
    st.markdown("For CSV files (with 'url' column header):")
    st.code("url\nhttps://example1.com\nhttps://example2.com", language="text")
    
    # URL input methods
    input_method = st.radio("Choose input method:", ["Upload File", "Paste URLs"])
    
    urls_to_check = []
    
    if input_method == "Upload File":
        uploaded_file = st.file_uploader(
            "Upload file with URLs",
            type=['txt', 'csv'],
            help="One URL per line (txt) or CSV with 'url' column"
        )
        
        if uploaded_file:
            # Use utf-8-sig to handle BOM characters
            content = uploaded_file.read().decode('utf-8-sig')
            file_lower = uploaded_file.name.lower()
            
            if file_lower.endswith('.csv'):
                # Use pandas to properly parse CSV files with headers
                import io
                try:
                    df = pd.read_csv(io.StringIO(content))
                    # Look for a 'url' column (case-insensitive)
                    columns_lower = {col.lower(): col for col in df.columns}
                    if 'url' in columns_lower:
                        url_col = columns_lower['url']
                        urls_to_check = [
                            str(u).strip().strip('"\'')
                            for u in df[url_col].dropna()
                            if str(u).strip()
                        ]
                    else:
                        # Fallback: use first column if no 'url' column found
                        first_col = df.columns[0]
                        urls_to_check = [
                            str(u).strip().strip('"\'')
                            for u in df[first_col].dropna()
                            if str(u).strip()
                        ]
                        st.warning(f"No 'url' column found in CSV. Using first column: '{first_col}'")
                except Exception as e:
                    logging.exception("Failed to parse CSV file")
                    st.error(f"Failed to parse CSV file: {e}")
                    urls_to_check = []
            else:
                # Plain text file: one URL per line
                urls_to_check = [
                    line.strip().strip('"\'')
                    for line in content.split('\n')
                    if line.strip()
                ]
            
            if urls_to_check:
                st.success(f"Loaded {len(urls_to_check)} URLs")
    
    else:
        urls_text = st.text_area(
            "Paste URLs (one per line)",
            height=200,
            placeholder="https://example1.com\nhttps://example2.com\nhttps://example3.com"
        )
        if urls_text:
            # Remove BOM if present and strip quotes from URLs
            clean_text = urls_text.lstrip('\ufeff')
            urls_to_check = [
                line.strip().strip('"\'')
                for line in clean_text.split('\n')
                if line.strip()
            ]
    
    if urls_to_check:
        st.info(f"Ready to analyze {len(urls_to_check)} URLs")
        
        if st.button("Analyze All URLs", type="primary"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            results = []
            errors = []
            
            # First, filter out invalid URLs
            valid_urls = []
            valid_indices = []
            for i, url in enumerate(urls_to_check):
                if not url.startswith(('http://', 'https://')):
                    errors.append(f"Skipping invalid URL: {url}")
                    results.append({
                        'URL': url,
                        'Status': 'Invalid',
                        'Prediction Label': 'Invalid',
                        'Reachability': 'N/A',
                        'Risk Level': 'Unknown'
                    })
                else:
                    valid_urls.append(url)
                    valid_indices.append(i)
                    results.append(None)  # Placeholder
            
            # Update progress for validation phase
            progress_bar.progress(0.1)
            status_text.text(f"Validated URLs. Analyzing {len(valid_urls)} valid URLs...")
            
            # Batch predict all valid URLs
            if valid_urls:
                try:
                    predictions = predict_urls(valid_urls, use_model=use_model)
                    
                    # Process each prediction result
                    for batch_idx, (url, prediction) in enumerate(zip(valid_urls, predictions)):
                        # Update progress
                        progress_pct = 0.1 + (0.9 * (batch_idx + 1) / len(valid_urls))
                        progress_bar.progress(progress_pct)
                        status_text.text(f"Processing result {batch_idx + 1} of {len(valid_urls)}...")
                        
                        original_idx = valid_indices[batch_idx]
                        
                        label = prediction.get('label', 'benign').lower()
                        confidence = float(prediction.get('confidence', 0.0))
                        reachability = prediction.get('reachability', {})
                        
                        # Check for prediction errors
                        if prediction.get('error'):
                            errors.append(f"Failed to classify {url}: {prediction.get('error')}")
                        
                        # Check if label indicates phishing/malicious
                        is_phishing = not _is_benign_label(label)
                        # Explicitly check reachability: None means unknown, True/False are explicit
                        reachable = reachability.get('reachable')
                        if reachable is True:
                            status = 'Phishing' if is_phishing else 'Safe'
                            if label == 'unknown':
                                status = 'Error'
                            risk_level = 'High' if is_phishing else 'Low'
                            reachability_display = 'Reachable'
                        elif reachable is False:
                            status = 'Unreachable'
                            risk_level = 'Unknown'
                            reachability_display = 'Unreachable'
                        else:
                            # reachable is None - unknown status
                            status = 'Unknown'
                            risk_level = 'Unknown'
                            reachability_display = 'Unknown'
                        
                        results[original_idx] = {
                            'URL': url[:50] + '...' if len(url) > 50 else url,
                            'Status': status,
                            'Prediction Label': _get_model_label_display(label),
                            'Reachability': reachability_display,
                            'Risk Level': risk_level
                        }
                except Exception as e:
                    logging.exception("Batch URL prediction failed")
                    # Fill in error results for all pending URLs
                    for batch_idx, url in enumerate(valid_urls):
                        original_idx = valid_indices[batch_idx]
                        if results[original_idx] is None:
                            errors.append(f"Failed to classify {url}")
                            results[original_idx] = {
                                'URL': url[:50] + '...' if len(url) > 50 else url,
                                'Status': 'Error',
                                'Prediction Label': 'Error',
                                'Reachability': 'Unknown',
                                'Risk Level': 'Unknown'
                            }
            
            progress_bar.progress(1.0)
            st.success(f"Analysis complete! Processed {len(urls_to_check)} URLs")

            if errors:
                with st.expander("Issues encountered"):
                    for err in errors:
                        st.warning(err)

            results_df = pd.DataFrame(results)
            st.dataframe(results_df, use_container_width=True, hide_index=True)

            phishing_count = sum(1 for r in results if r['Status'] == 'Phishing')
            safe_count = sum(1 for r in results if r['Status'] == 'Safe')
            error_count = len(results) - phishing_count - safe_count

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total URLs", len(results))
            with col2:
                st.metric("Phishing Detected", phishing_count)
            with col3:
                st.metric("Safe URLs", safe_count)

            if error_count:
                st.caption(f"{error_count} entries failed to predict")

            csv = results_df.to_csv(index=False)
            st.download_button(
                label="Download Results (CSV)",
                data=csv,
                file_name="url_analysis_results.csv",
                mime="text/csv"
            )

# Sidebar
# with st.sidebar:
#     st.markdown("### Common URL Phishing Signs")
#     st.markdown("""
#     - Using HTTP instead of HTTPS
#     - Misspelled domain names
#     - Excessive subdomains
#     - Suspicious TLDs (.tk, .ml, .ga)
#     - URLs with @ symbols
#     - Shortened/obfuscated URLs
#     - URLs with IP addresses
#     """)