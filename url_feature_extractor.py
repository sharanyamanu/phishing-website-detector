from urllib.parse import urlparse

def extract_features_from_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    features = [
        len(url),  # Total URL length
        len(domain),  # Domain length
        url.count('.'),  # Number of dots
        url.count('-'),  # Number of hyphens
        url.count('@'),  # Number of @ symbols
        url.count('?'),  # Number of query params
        url.count('='),  # Number of equal signs
        int(parsed.scheme == 'https'),  # HTTPS presence (1 = yes, 0 = no)
        int(any(keyword in url.lower() for keyword in ['verify', 'login', 'update', 'secure'])),  # Phishing keywords
        int(any(short in url for short in ['bit.ly', 'tinyurl.com', 't.co']))  # Known shorteners
    ]

    return features
