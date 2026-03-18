import pandas as pd
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from ucimlrepo import fetch_ucirepo

# 🔹 1. Load dataset
data = fetch_ucirepo(id=967)  # Phishing Websites Data Set (UCI)
df = data.data.features.copy()
df['label'] = data.data.targets.values.ravel()

# 🔹 2. Simulate a URL column (for feature extraction)
df['url'] = 'http://example.com/' + df.index.astype(str)

# 🔹 3. Feature extraction from URLs
def extract_10_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    return [
        len(url),  # Total length of URL
        len(domain),  # Length of domain
        url.count('.'),  # Number of dots
        url.count('-'),  # Number of hyphens
        url.count('@'),  # Number of @ symbols
        url.count('?'),  # Number of question marks
        url.count('='),  # Number of '='
        int(parsed.scheme == 'https'),  # Whether HTTPS is used
        int(any(word in url.lower() for word in ['verify', 'login', 'update', 'secure'])),  # Phishy keywords
        int(any(short in url for short in ['bit.ly', 'tinyurl.com', 't.co']))  # URL shorteners
    ]

# Apply the feature extractor
X = df['url'].apply(extract_10_features).tolist()
X = pd.DataFrame(X, columns=[
    'url_length', 'domain_length', 'count_dots', 'count_hyphens',
    'count_at', 'count_question', 'count_equals', 'has_https',
    'has_suspicious_words', 'is_tinyurl'
])
y = df['label']

# 🔹 4. Train/Test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 🔹 5. Scaling
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 🔹 6. Model Training
model = RandomForestClassifier(class_weight='balanced', random_state=42)
model.fit(X_train_scaled, y_train)

# 🔹 7. Evaluation
y_pred = model.predict(X_test_scaled)
accuracy = accuracy_score(y_test, y_pred)
print("🎯 Model Accuracy:", accuracy)
print("\n🧾 Classification Report:\n", classification_report(y_test, y_pred))

# 🔹 8. Save Model & Scaler
joblib.dump(model, 'phishing_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
print("💾 Model and scaler saved with 10 features.")
