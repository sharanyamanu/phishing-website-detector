import re

def extract_features(url):
    features = {}

    features['length'] = len(url)
    features['has_https'] = 1 if "https" in url else 0
    features['num_dots'] = url.count('.')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['has_at'] = 1 if '@' in url else 0
    features['has_hyphen'] = 1 if '-' in url else 0
    features['num_subdirs'] = url.count('/')

    return list(features.values())