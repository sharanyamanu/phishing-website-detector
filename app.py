from flask import Flask, request, render_template
import requests, os, datetime, time
from dotenv import load_dotenv
from url_features import extract_features

load_dotenv()
app = Flask(__name__)

VT_API_KEY = "75625dbbb1602df8dd6172e79340f48764619da21ceed5c5c4480589a6f80e96"

recent_scans = []


# 🔥 ML MODEL (improved)
def ml_predict(url):
    score = 0

    if "@" in url: score += 3
    if "-" in url: score += 1
    if url.count('.') > 3: score += 1
    if any(char.isdigit() for char in url): score += 1
    if "login" in url or "verify" in url or "secure" in url: score += 2
    if "http://" in url: score += 1

    # strong keyword detection
    if "malware" in url or "eicar" in url:
        return "PHISHING"

    return "PHISHING" if score >= 3 else "SAFE"


# 🔍 VirusTotal
def check_virustotal(url):
    try:
        headers = {"x-apikey": VT_API_KEY}

        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if response.status_code != 200:
            print("POST Error:", response.text)
            return None

        analysis_id = response.json()["data"]["id"]

        # 🔥 Wait until analysis completes
        for _ in range(10):
            report = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )

            data = report.json()
            status = data["data"]["attributes"]["status"]

            if status == "completed":
                return data["data"]["attributes"]["stats"]

            time.sleep(2)

        return None

    except Exception as e:
        print("ERROR:", e)
        return None


@app.route('/')
def home():
    return render_template('index.html', scans=recent_scans)


@app.route('/predict', methods=['POST'])
def predict():
    url = request.form.get('url')

    # ✅ Validate URL
    if not url or not url.startswith("http"):
        return render_template(
            'index.html',
            error="⚠️ Enter valid URL (include http/https)",
            scans=recent_scans
        )

    vt = check_virustotal(url)
    ml_result = ml_predict(url)

    # ❌ If API fails
    if vt is None:
        return render_template(
            'index.html',
            error="⚠️ API error or invalid key",
            scans=recent_scans
        )

    # 📊 Extract stats
    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    harmless = vt.get("harmless", 0)

    total = malicious + suspicious + harmless

    # 🔥 CORRECT SCORE (HYBRID)
    vt_score = ((malicious + suspicious) / total) * 100 if total else 0

    # ML influence
    if ml_result == "PHISHING":
        vt_score += 40

    score = min(int(vt_score), 100)

    # 🔥 FINAL STATUS (CONSISTENT)
    if malicious > 0:
        status = "DANGEROUS"
    elif suspicious > 0 or ml_result == "PHISHING":
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    # Save history
    recent_scans.insert(0, {
        "url": url,
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "status": status
    })

    return render_template(
        'index.html',
        result=True,
        url=url,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        score=score,
        status=status,
        ml=ml_result,
        scans=recent_scans[:5]
    )


if __name__ == '__main__':
    app.run(debug=True)