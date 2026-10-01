#libraries
from flask import Flask, render_template, request, jsonify
import pandas as pd
import pickle
from features import featureExtraction
from whois_utils import get_whois_info

app = Flask(__name__)

#load both model
dt_model = pickle.load(open("dt_model.pkl", "rb"))
rf_model = pickle.load(open("rf_model.pkl", "rb"))

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    url = request.form["url"]
    model_choice = request.form["model"]

    #Extract features
    features = featureExtraction(url)

    feature_names = [
        "having_IP",
        "have_At",
        "get_Length",
        "get_Depth",
        "https",
        "suspicious",
        "hyphen",
        "subdomain",
        "https_in_domain",
        "dot_count",
        "digit_ratio",
        "host_length",
        "path_length",
        "digit_count",
        "entropy",
        "special_chars",
        "shortened",
        "suspicious_tld"
    ]

    features_df = pd.DataFrame([features], columns=feature_names)

    #convert features to readable format
    display_names = [
        "IP Address",
        "@ Symbol",
        "URL Length",
        "Depth",
        "HTTPS",
        "Suspicious Words",
        "Hyphen in Domain",
        "Subdomain Count",
        "HTTPS in Domain",
        "Dot Count",
        "Digit Ratio",
        "Hostname Length",
        "Path Length",
        "Digit Count",
        "Entropy",
        "Special Characters",
        "Shortened URL",
        "Suspicious TLD"
    ]
    features_values = []
    for i, val in enumerate(features):
        #round only floating-point values for display
        if isinstance(val, float):
            val = round(val, 2)
        features_values.append((display_names[i], val))

    
    # Comparison Mode (Random Forest + Decision Tree)

    if model_choice == "both":

        rf_result = rf_model.predict(features_df)[0]
        rf_confidence = round(max(rf_model.predict_proba(features_df)[0]) * 100, 2)
        # Random Forest Risk Level
        rf_risk_level = "HIGH" if rf_result == 1 else "LOW"
        rf_risk_color = "#ff3838" if rf_result == 1 else "#5cd65c"

        dt_result = dt_model.predict(features_df)[0]
        dt_confidence = round(max(dt_model.predict_proba(features_df)[0]) * 100, 2)
        # Decision Tree Risk Level
        dt_risk_level = "HIGH" if dt_result == 1 else "LOW"
        dt_risk_color = "#ff3838" if dt_result == 1 else "#5cd65c"


        rf_prediction = "Phishing Website" if rf_result == 1 else "Legitimate Website"

        dt_prediction = "Phishing Website" if dt_result == 1 else "Legitimate Website"

        metrics = {}

        with open("accuracy.txt", "r") as f:
            for line in f:
                line = line.strip()

                if line == "":
                    continue

                key, value = line.split(":")
                metrics[key] = round(float(value) * 100, 2)
        
        if rf_result == 0 and dt_result == 0:
            page_bg = "safe-bg"
        else:
            page_bg = "phishing-bg"

        # Get WHOIS information
        whois_info = get_whois_info(url)

        # Security Analysis
        analysis = []

        # Domain Age
        if isinstance(whois_info["domain_age"], str) and "days" in whois_info["domain_age"]:

            age_days = int(whois_info["domain_age"].split()[0])

            if age_days < 180:
                analysis.append(("warning",
                    f"Domain age is only {age_days} days. Newly registered domains are commonly used in phishing attacks."
                ))

            elif age_days < 730:
                analysis.append(("warning",
                    f"Domain age is {age_days} days. Relatively new domains deserve additional caution."
                ))

        else:

            analysis.append((
                "info",
                "Domain registration information could not be retrieved."
            ))


        # Suspicious Words
        if features[5] == 1:
            analysis.append(("warning","Suspicious keywords detected in the URL."))

        # Suspicious TLD
        if features[17] == 1:
            analysis.append(("warning","Suspicious top-level domain detected."))

        # Shortened URL
        if features[16] == 1:
            analysis.append(("warning","URL shortening service detected."))

        # Entropy
        if features[14] > 4.2:
            analysis.append(("warning",
                f"High URL entropy detected ({features[14]:.2f})."))

        # Digit Ratio
        if features[10] > 0.20:
            analysis.append(("warning",
                f"High digit ratio detected ({features[10]:.2f})."))

        # HTTPS
        if features[4] == 0:
            analysis.append(("warning","HTTPS is not enabled."))

        # Hyphen
        if features[6] == 1:
            analysis.append(("warning","Hyphen detected in domain name."))

        # HTTPS in Domain
        if features[8] == 1:
            analysis.append(("warning",
                "The word 'https' appears inside the domain name."))
            
        # If no suspicious indicators were found
        if len(analysis) == 0:
            analysis.append((
                "positive",
                "No suspicious security indicators were detected during analysis."
            ))
            
        return render_template(
            "comparison.html",

            features=features_values,

            page_bg=page_bg,

            rf_risk_level=rf_risk_level,
            rf_risk_color=rf_risk_color,

            dt_risk_level=dt_risk_level,
            dt_risk_color=dt_risk_color,

            url=url,

            rf_prediction=rf_prediction,
            rf_confidence=rf_confidence,

            dt_prediction=dt_prediction,
            dt_confidence=dt_confidence,

            rf_accuracy=metrics["RF_Accuracy"],
            rf_precision=metrics["RF_Precision"],
            rf_recall=metrics["RF_Recall"],
            rf_f1=metrics["RF_F1"],
            rf_cv=metrics["RF_CV"],

            dt_accuracy=metrics["DT_Accuracy"],
            dt_precision=metrics["DT_Precision"],
            dt_recall=metrics["DT_Recall"],
            dt_f1=metrics["DT_F1"],
            dt_cv=metrics["DT_CV"],

            domain_age=whois_info["domain_age"],
            registration_length=whois_info["registration_length"],
            analysis=analysis,
        )

    
    # Single Model Mode

    elif model_choice == "dt":
        model = dt_model
        model_name = "Decision Tree"

    else:
        model = rf_model
        model_name = "Random Forest"

    # Prediction
    result = model.predict(features_df)[0]
    output = "Phishing Website" if result == 1 else "Legitimate Website"

    # Prediction Confidence
    probabilities = model.predict_proba(features_df)[0]
    confidence = round(max(probabilities) * 100, 2)

    #Get WHOIS information
    whois_info = get_whois_info(url)


#========================================================================================================
    # SECURITY ANALYSIS

    analysis = []
    risk_score = 0

    # 1. DOMAIN AGE (Highest Priority)
    if isinstance(whois_info["domain_age"], str) and "days" in whois_info["domain_age"]:

        age_days = int(whois_info["domain_age"].split()[0])

        if age_days < 180:
            risk_score += 2
            analysis.append((
                "warning",
                f"Domain age is only {age_days} days. Newly registered domains are commonly used in phishing attacks."
            ))

        elif age_days < 730:
            risk_score += 1
            analysis.append((
                "warning",
                f"Domain age is {age_days} days. Relatively new domains deserve additional caution."
            ))

    else:
        analysis.append((
            "info",
            "Domain registration information could not be retrieved."
        ))


    # 2. SUSPICIOUS KEYWORDS
    if features[5] == 1:
        risk_score += 2
        analysis.append((
            "warning",
            "Suspicious keywords detected in the URL."
        ))


    # 3. SUSPICIOUS TLD
    if features[17] == 1:
        risk_score += 2
        analysis.append((
            "warning",
            "Suspicous top-level domain detected."
        ))


    # 4. URL SHORTENER
    if features[16] == 1:
        risk_score += 2
        analysis.append((
            "warning",
            "URL shortening service detected."
        ))


    # 5. URL ENTROPY
    entropy = features[14]

    if entropy > 4.2:
        risk_score += 1
        analysis.append((
            "warning",
            f"High URL entropy detected ({entropy:.2f})."
        ))


    # 6. DIGIT RATIO
    ratio = features[10]

    if ratio > 0.20:
        risk_score += 1
        analysis.append((
            "warning",
            f"High digit ratio detected ({ratio:.2f})."
        ))


    # 7. HTTPS
    if features[4] == 0:
        risk_score += 1
        analysis.append((
            "warning",
            "HTTPS is not enabled."
        ))


    # 8. HYPHEN
    if features[6] == 1:
        risk_score += 1
        analysis.append((
            "warning",
            "Hyphen detected in domain name."
        ))


    # 9. HTTPS INSIDE DOMAIN
    if features[8] == 1:
        risk_score += 2
        analysis.append((
            "warning",
            "The word 'https' appears inside the domain name, a known phishing technique."
        ))
    
    # If no suspicious indicators were found
    if len(analysis) == 0:
        analysis.append((
            "positive",
            "No suspicious security indicators were detected during analysis."
        ))
    
#========================================================================================================
    # OVERALL RISK LEVELS

    if result == 1:

        # If ML predicts phishing, always show HIGH
        risk_level = "HIGH"
        risk_color = "#ff3838"

    else:

        if risk_score <= 2:
            risk_level = "LOW"
            risk_color = "#5cd65c"

        elif risk_score <= 5:
            risk_level = "MEDIUM"
            risk_color = "#ff9800"

        else:
            risk_level = "HIGH"
            risk_color = "#ff3838"

    print(f"Risk Level: {risk_level}, Risk Color: {risk_color}")

    return render_template(
        "result.html",
        prediction=output,
        url=url,
        model_name=model_name,
        model_choice=model_choice,
        features=features_values,
        domain_age=whois_info["domain_age"],
        registration_length=whois_info["registration_length"],
        analysis = analysis,

        risk_level = risk_level,
        risk_color = risk_color,
        risk_score = risk_score,

        confidence = confidence
    )

#========================================================================================================
@app.route("/get_accuracy", methods=["POST"])
def get_accuracy():
    model_choice = request.form["model"]
    metrics = {}

    with open("accuracy.txt", "r") as f:
        for line in f:
            line = line.strip()

            if line == "":
                continue
            key, value = line.split(":")
            metrics[key] = round(float(value) * 100, 2)
    
    if model_choice == "dt":
        return jsonify({
            "accuracy": metrics["DT_Accuracy"],
            "precision": metrics["DT_Precision"],
            "recall": metrics["DT_Recall"],
            "f1": metrics["DT_F1"],
            "cv": metrics["DT_CV"]
        })
    
    else:
        return jsonify({
            "accuracy": metrics["RF_Accuracy"],
            "precision": metrics["RF_Precision"],
            "recall": metrics["RF_Recall"],
            "f1": metrics["RF_F1"],
            "cv": metrics["RF_CV"]
        })
    
if __name__ == "__main__":
    app.run(debug=True)