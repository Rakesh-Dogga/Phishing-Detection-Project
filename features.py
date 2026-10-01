import re
import math 
from urllib.parse import urlparse
from datetime import datetime
import whois

# 1. check IP address in URL
def havingIP(url):
    try:
        ip = re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})', url)
        if ip:
            parts = ip[0].split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                return 1
    except:
        pass
    return 0 
    
# 2. check @ symbol
def haveAtSign(url):
    if "@" in url:
        return 1
    return 0

# 3. Url length
def getLength(url):
    return len(url)

# 4. Url depth
def getDepth(url):
    path = urlparse(url).path
    return path.count("/")

# 5. Check https
def checkHTTPS(url):
    if url.lower().startswith("https://"):
        return 1                #secure
    else:
        return 0                #not secure
    
#6. suspicious words
def suspiciousWords(url):
    keywords = ["login","verify","secure","account","bank","update","signin","confirm","password","ebayisapi","webscr"]
    for word in keywords:
        if word in url.lower():
            return 1            #suspicious
    return 0                    #normal

# 7. hyphen in domain
def hasHyphen(url):
    domain = urlparse(url).netloc
    return 1 if domain.count('-') >= 1 else 0

# 8. subdomain count
def subdomainCount(url):
    domain = urlparse(url).netloc
    return domain.count('.')

# 9. https in domain(fake trick)
def httpsInDomain(url):
    domain = urlparse(url).netloc
    if "https" in domain:
        return 1        
    else: 
        return 0        

# 10. dot count 
def dotCount(url):
    return url.count('.')
    
#11. digit ratio
def digitRatio(url):
    digits = sum(c.isdigit() for c in url) 
    return digits / len(url)

#12 Hostname length
def hostLength(url):
    domain = urlparse(url).netloc
    return len(domain)

#13 Path length
def pathLength(url):
    path = urlparse(url).path
    return len(path)

#14 Digit Count
def digitCount(url):
    return sum(c.isdigit() for c in url)

#15. entropy for randomness characters in the URL
def urlEntropy(url):
    prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
    entropy = -sum([p * math.log2(p) for p in prob])
    return entropy

#16. special character 
def specialCharCount(url):
    return len(re.findall(r'[?&=%]', url))

#17. shortened URL detection
def isShortened(url):
    shorteners = ["bit.ly","tinyurl","goo.gl","t.co","ow.ly"]
    return 1 if any(s in url for s in shorteners) else 0

#18. suspicious top-level-domains
def suspiciousTLD(url):
    suspicious = [".tk",".ml",".ga",".cf",".gq"]
    domain = urlparse(url).netloc
    return 1 if any(domain.endswith(tld) for tld in suspicious) else 0

#19 Domain Age - WHOIS feature
def domainAge(url):
    try:
        domain = urlparse(url).netloc

        w = whois.whois(domain)

        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        age_days = (datetime.now() - creation_date).days
        return age_days
    except:
        return 0

#20 Registration length Feature - WHOIS Feature
def registrationLength(url):
    try:
        domain = urlparse(url).netloc

        w = whois.whois(domain)

        creation_date = w.creation_date
        expiration_date = w.expiration_date

        if isinstance(creation_date,list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        registration_days = (expiration_date - creation_date).days

        return registration_days
    except:
        return 0

# main funtuion
def featureExtraction(url):
    features = []

    features.append(havingIP(url))          #0 or 1
    features.append(haveAtSign(url))        #0 or 1
    features.append(getLength(url))         # raw length
    features.append(getDepth(url))          # raw count
    features.append(checkHTTPS(url))        #0 or 1
    features.append(suspiciousWords(url))   #0 or 1
    features.append(hasHyphen(url))         #0 or 1
    features.append(subdomainCount(url))    # raw count
    features.append(httpsInDomain(url))     #0 or 1
    features.append(dotCount(url))          # raw count

    features.append(digitRatio(url))
    features.append(hostLength(url))
    features.append(pathLength(url))
    features.append(digitCount(url))
    features.append(urlEntropy(url))
    features.append(specialCharCount(url))
    features.append(isShortened(url))
    features.append(suspiciousTLD(url))     

    # #WHOIS features
    # features.append(domainAge(url))
    # features.append(registrationLength(url))

    return features
