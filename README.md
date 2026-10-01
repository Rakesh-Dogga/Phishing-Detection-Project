# Phishing Website Detection using Machine Learning

A machine learning-based web application that analyzes website URLs and classifies them as either **Phishing Website** or **Legitimate Website**.

The system extracts multiple URL-based features such as URL length, IP address presence, HTTPS usage, suspicious words, subdomain count, URL entropy, special characters, shortened URL usage, and suspicious TLDs. These features are provided to trained machine learning models to generate the prediction.

The application is developed using **Python, Flask, HTML, CSS, and Machine Learning**. It provides users with a simple web interface where they can enter a URL, select a machine learning model, and view the detection result and model performance.

## Project Objective

The main objective of this project is to develop a machine learning-based system that can identify potentially phishing URLs by analyzing their structural and lexical characteristics. The system will provide a convenient interface for testing URLs and displaying the classification results.

## Features

- **URL Input:** Allows users to enter a website URL for analysis.
- **URL Validation:** Checks whether the entered URL follows the required format.
- **Machine Learning Model Selection:** Allows users to select between Random Forest and Decision Tree models.
- **URL Feature Extraction:** Extracts important characteristics from the URL, including IP address presence, URL length, HTTPS usage, suspicious words, hyphens, subdomains, dots, digit ratio, entropy, special characters, shortened URLs, and suspicious TLDs.
- **Phishing Detection:** Classifies the submitted URL as either a phishing website or a legitimate website.
- **Model Comparison:** Provides prediction results from the available machine learning models.
- **Prediction Confidence:** Displays the confidence associated with the model prediction.
- **URL Feature Analysis:** Displays the extracted numerical features of the submitted URL.
- **Model Performance:** Displays accuracy, precision, recall, F1 score, and cross-validation results.
- **WHOIS Information:** Displays available domain-related information such as domain age and registration length.
- **Security Analysis:** Displays detected suspicious indicators associated with the analyzed URL.
- **Repeated URL Testing:** Allows users to return to the home page and analyze another URL.
