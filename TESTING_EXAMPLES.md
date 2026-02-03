# URL Detection Testing Examples

This document provides test examples for the URL detection feature across all 4 categories that the ML model can predict.

## Label Categories

The ML model (trained on Kaggle phishing dataset) classifies URLs into 4 categories:

| Label | Numeric | Category | Description |
|-------|---------|----------|-------------|
| **0** | Benign | Safe | Legitimate, safe websites |
| **1** | Defacement | Hacked | Websites that have been compromised/defaced |
| **2** | Phishing | Danger | Phishing attempts to steal credentials |
| **3** | Malware | Virus | URLs distributing malware/viruses |

## Test Examples by Category

### Category 0: Benign (Safe URLs)

**Expected Result:**
- Status: "URL Appears Safe"
- Display Label: "Benign (Safe)"
- Background: Green

**Example URLs to Test:**
```
https://google.com
https://facebook.com
https://github.com
https://stackoverflow.com
https://microsoft.com
https://amazon.com
https://wikipedia.org
https://youtube.com
```

**Features that indicate benign:**
- Well-known domain names
- HTTPS encryption
- Normal domain structure
- No suspicious keywords
- Valid SSL certificates

---

### Category 1: Defacement (Hacked Sites)

**Expected Result:**
- Status: "Dangerous Website Detected"
- Display Label: "Defacement (Hacked)"
- Background: Red

**Example Patterns (Simulated for testing):**
```
https://compromised-site.com/hacked.html
https://old-vulnerable-site.org/index.php?defaced=1
```

**Features that indicate defacement:**
- Legitimate sites that have been compromised
- Often includes unusual paths or parameters
- May contain injection vulnerabilities
- Changed content from original site

**Note:** Real defaced sites change frequently. Use the Model mode in the UI to test with URLs that the ML model predicts as defacement based on URL structure patterns.

---

### Category 2: Phishing (Credential Theft)

**Expected Result:**
- Status: "Dangerous Website Detected"
- Display Label: "Phishing (Danger)"
- Background: Red

**Example Patterns to Test:**
```
https://facebook-security-verify.com/login
https://paypal-account-confirm.xyz/secure
https://amazon-update-billing.tk/verify
https://gooogle.com (typosquatting)
https://microsоft.com (homograph attack - Cyrillic 'о')
```

**Features that indicate phishing:**
- Typosquatting (slight misspellings of brands)
- Homograph attacks (lookalike characters)
- Suspicious TLDs (.tk, .ml, .ga, .xyz)
- Keywords like "verify", "secure", "login", "update"
- URL shorteners hiding final destination
- Excessive subdomains

---

### Category 3: Malware (Virus Distribution)

**Expected Result:**
- Status: "Dangerous Website Detected"
- Display Label: "Malware (Virus)"
- Background: Red

**Example Patterns to Test:**
```
https://free-download-software.ml/installer.exe
https://crack-tools.tk/keygen
https://192.168.1.100:8080/payload.zip
```

**Features that indicate malware:**
- Suspicious file downloads in URL
- IP addresses instead of domains
- Non-standard ports
- Keywords like "crack", "keygen", "free-download"
- Suspicious TLDs commonly used for malware
- Very long URLs with encoded content

---

## How to Test

### Testing with Model Mode (ML-based)

1. Open the URL Detection page
2. Select **"Model (ML-based)"** mode
3. Enter one of the test URLs above
4. Click "Check URL"
5. Verify the result matches the expected category

### Testing with API Mode (Safe Browsing)

1. Open the URL Detection page
2. Select **"API (Safe Browsing)"** mode
3. Enter a URL from the test examples
4. Click "Check URL"
5. Note: Safe Browsing API uses Google's threat database, results may differ from ML model

### Batch Testing

You can test multiple URLs at once:

1. Go to the "Batch URL Analysis" tab
2. Paste multiple URLs (one per line) or upload a file:
```
https://google.com
https://facebook2.com
https://paypal-verify.tk
https://free-malware.ml
```
3. Click "Analyze All URLs"
4. Review the results table

---

## Understanding the Results

### Safe Result (Label 0)
```
✓ URL Appears Safe
  Benign (Safe)
  
  Risk Score: 0-20/100
  No significant risk indicators found
```

### Dangerous Result (Labels 1, 2, 3)
```
⚠ Dangerous Website Detected
  [Defacement (Hacked) | Phishing (Danger) | Malware (Virus)]
  
  Risk Score: 40+/100
  Multiple risk indicators detected
```

---

## Simulating Different Labels for Testing

Since you mentioned the dataset is from Kaggle, the ML model has learned patterns from that dataset. To test different categories:

1. **For Benign (0):** Use well-known legitimate sites
2. **For Defacement (1):** Use URLs with vulnerability patterns or unusual paths
3. **For Phishing (2):** Use typosquatted domains or suspicious login pages
4. **For Malware (3):** Use URLs with download patterns or suspicious file extensions

The ML model uses URL features like:
- URL length
- Domain length
- Number of subdomains
- Presence of digits/hyphens
- Suspicious keywords
- HTTPS presence
- Port numbers

---

## Notes on the Kaggle Dataset

The model was trained on a Kaggle phishing detection dataset that includes:
- **Benign URLs:** From Alexa top sites and verified safe sources
- **Defacement URLs:** From zone-h.org and similar defacement archives
- **Phishing URLs:** From PhishTank and OpenPhish databases
- **Malware URLs:** From URLhaus and malware distribution trackers

The model learns patterns in URL structure rather than checking against live threat databases, which means it can detect new threats based on suspicious patterns even if they're not in a database yet.

---

## Troubleshooting

### All URLs show as "Dangerous"
This was the bug that was fixed! If you see this:
- Make sure you're using the latest version with the label mapping fix
- Check that the model file is properly loaded
- Verify you're in "Model (ML-based)" mode

### Model returns numeric labels
This should no longer happen after the fix. If you see raw numbers (0, 1, 2, 3) instead of category names:
- Check the browser console for warnings
- Verify the predictor.py LABEL_MAP is present
- Ensure the latest code changes are deployed

---

## Example Test Session

Here's a complete test session you can run:

```python
# Test script to verify label handling
test_urls = {
    0: "https://google.com",           # Should be Benign
    1: "https://defaced-site.org",     # Would be Defacement if model predicts
    2: "https://paypal-verify.tk",     # Likely Phishing
    3: "https://malware-site.ml/exe"   # Likely Malware
}

# Run each through the URL Detection page and verify:
# - Correct status message
# - Correct label display
# - Correct risk indicators
# - Appropriate recommendations
```

---

## Quick Reference Card

| Category | Code | Display | Color | Risk Level |
|----------|------|---------|-------|------------|
| Benign | 0 | Benign (Safe) | Green | Low |
| Defacement | 1 | Defacement (Hacked) | Red | High |
| Phishing | 2 | Phishing (Danger) | Red | High |
| Malware | 3 | Malware (Virus) | Red | High |

---

For more information about the model and dataset, refer to the Kaggle dataset documentation.
