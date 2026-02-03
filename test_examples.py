#!/usr/bin/env python3
"""
Quick test script for URL label categories
This simulates the label mapping behavior to help understand each category
"""

# Label mapping from the fix
LABEL_MAP = {
    '0': 'benign',      # Safe/legitimate URL
    '1': 'defacement',  # Website defacement/hacking
    '2': 'phishing',    # Phishing attempt
    '3': 'malware',     # Malware/virus distribution
    0: 'benign',
    1: 'defacement',
    2: 'phishing',
    3: 'malware',
}

# Display labels
DISPLAY_MAP = {
    'benign': 'Benign (Safe)',
    'defacement': 'Defacement (Hacked)',
    'phishing': 'Phishing (Danger)',
    'malware': 'Malware (Virus)'
}

# Test examples for each category
TEST_EXAMPLES = {
    0: {
        'category': 'Benign (Safe)',
        'description': 'Legitimate, safe websites',
        'examples': [
            'https://google.com',
            'https://facebook.com',
            'https://github.com',
            'https://amazon.com',
            'https://microsoft.com',
        ],
        'status': 'Safe',
        'features': [
            'Well-known domain names',
            'HTTPS encryption',
            'Normal domain structure',
            'Valid SSL certificates',
        ]
    },
    1: {
        'category': 'Defacement (Hacked)',
        'description': 'Websites that have been compromised or hacked',
        'examples': [
            'https://compromised-site.com/hacked.html',
            'https://vulnerable-cms.org/wp-admin/defaced',
            'https://old-site.net/index.php?hacked=true',
        ],
        'status': 'Not Safe',
        'features': [
            'Legitimate sites that are compromised',
            'Unusual paths or parameters',
            'Injection vulnerability patterns',
            'Changed content indicators',
        ]
    },
    2: {
        'category': 'Phishing (Danger)',
        'description': 'Phishing attempts to steal credentials',
        'examples': [
            'https://paypal-verify.tk/login',
            'https://facebook-security.ml/verify',
            'https://gooogle.com',  # typosquatting
            'https://amazon-account-update.xyz',
            'https://secure-login-microsoft.ga',
        ],
        'status': 'Not Safe',
        'features': [
            'Typosquatting (brand misspellings)',
            'Suspicious TLDs (.tk, .ml, .ga)',
            'Keywords: verify, secure, login, update',
            'Homograph attacks',
            'URL shorteners',
        ]
    },
    3: {
        'category': 'Malware (Virus)',
        'description': 'URLs distributing malware or viruses',
        'examples': [
            'https://free-download.ml/installer.exe',
            'https://crack-tools.tk/keygen',
            'https://192.168.1.100:8080/payload.zip',
            'https://suspicious-software.ga/download',
        ],
        'status': 'Not Safe',
        'features': [
            'Suspicious file downloads',
            'IP addresses instead of domains',
            'Non-standard ports',
            'Keywords: crack, keygen, free',
            'Encoded/obfuscated URLs',
        ]
    }
}

def print_separator(char='=', length=80):
    print(char * length)

def print_category_info(label_num):
    """Print detailed information about a category"""
    info = TEST_EXAMPLES[label_num]
    
    print_separator()
    print(f"CATEGORY {label_num}: {info['category']}")
    print_separator()
    
    # Show label conversion
    semantic_label = LABEL_MAP[label_num]
    display_label = DISPLAY_MAP[semantic_label]
    
    print(f"\n📋 Label Conversion:")
    print(f"   Numeric label: {label_num}")
    print(f"   Semantic label: {semantic_label}")
    print(f"   Display label: {display_label}")
    
    print(f"\n📝 Description:")
    print(f"   {info['description']}")
    
    print(f"\n🚦 Expected Status:")
    print(f"   {info['status']}")
    
    print(f"\n🔗 Example URLs to Test:")
    for url in info['examples']:
        print(f"   • {url}")
    
    print(f"\n🔍 Key Features/Indicators:")
    for feature in info['features']:
        print(f"   • {feature}")
    
    print()

def main():
    print("\n")
    print_separator('=')
    print("URL DETECTION - TESTING EXAMPLES FOR ALL 4 CATEGORIES")
    print_separator('=')
    print("\nThis guide shows test examples for each category the ML model can predict.")
    print("The model uses a Kaggle phishing dataset with 4 label classes.\n")
    
    # Print info for each category
    for label_num in [0, 1, 2, 3]:
        print_category_info(label_num)
    
    # Quick reference
    print_separator('=')
    print("QUICK REFERENCE")
    print_separator('=')
    print()
    print("| Label | Semantic    | Display              | Status   | Color |")
    print("|-------|-------------|----------------------|----------|-------|")
    for label_num in [0, 1, 2, 3]:
        semantic = LABEL_MAP[label_num]
        display = DISPLAY_MAP[semantic]
        status = TEST_EXAMPLES[label_num]['status']
        color = 'Green' if label_num == 0 else 'Red'
        print(f"| {label_num}     | {semantic:11} | {display:20} | {status:8} | {color:5} |")
    
    print()
    print_separator('=')
    print("HOW TO TEST")
    print_separator('=')
    print()
    print("1. Open the URL Detection page in the application")
    print("2. Select 'Model (ML-based)' mode")
    print("3. Enter one of the example URLs above")
    print("4. Click 'Check URL'")
    print("5. Verify the result matches the expected category")
    print()
    print("For batch testing:")
    print("- Go to 'Batch URL Analysis' tab")
    print("- Paste multiple URLs (one per line)")
    print("- Click 'Analyze All URLs'")
    print()
    print("NOTE: The actual label predicted by the ML model depends on the URL")
    print("features it extracts. Use these examples as a guide for testing.")
    print()
    print_separator('=')
    print()

if __name__ == '__main__':
    main()
