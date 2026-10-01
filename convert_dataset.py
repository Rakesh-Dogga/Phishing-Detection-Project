import pandas as pd
from features import featureExtraction


#========================================================================================================
# LOAD PHISHING URLS

data = pd.read_csv("dataset/phishtank.csv")

# Take 10,000 phishing URLs
phishing_urls = data["url"].dropna().sample(
    n=10000,
    random_state=42
)

rows = []

print("Processing phishing URLs...")

for url in phishing_urls:
    try:
        features = featureExtraction(str(url))
        features.append(1)      # Phishing label
        rows.append(features)
    except:
        continue

print("Phishing URLs converted:", len(rows))


#========================================================================================================
# LOAD LEGITIMATE URLS

tranco = pd.read_csv("dataset/tranco.csv", header=None)

# Column 1 contains domain names
domains = tranco[1].dropna().tolist()

# Convert domains to URLs
legit_urls = ["https://" + domain for domain in domains[:10000]]

legit_rows = []

print("Processing legitimate URLs...")

for url in legit_urls:
    try:
        features = featureExtraction(str(url))
        features.append(0)      # Legitimate label
        legit_rows.append(features)
    except:
        continue

print("Legitimate URLs converted:", len(legit_rows))

#========================================================================================================
# COMBINE DATASETS

rows.extend(legit_rows)

columns = [
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
    "suspicious_tld",
    "label"
]

df = pd.DataFrame(rows, columns=columns)

# Shuffle dataset
df = df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

# Save dataset
df.to_csv("dataset/data.csv", index=False)

print("Dataset created successfully.")
print("Total rows:", len(df))
print("Phishing records:", len(rows) - len(legit_rows))
print("Legitimate records:", len(legit_rows))