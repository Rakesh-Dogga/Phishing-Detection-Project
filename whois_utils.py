from urllib.parse import urlparse
from datetime import datetime
import whois

def get_whois_info(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)

        creation = w.creation_date
        expiration = w.expiration_date

        if isinstance(creation, list):
            creation = creation[0]

        if isinstance(expiration, list):
            expiration = expiration[0]

        if creation:
            domain_age = (datetime.now() - creation).days
        else:
            domain_age = "Unknown"

        if creation and expiration:
            registration_length = (expiration - creation).days
        else:
            registration_length = "Unknown"

        if isinstance(domain_age, int):
            domain_age_text = f"{domain_age} days ({domain_age / 365:.1f} years)"
        else:
            doamin_age_text = "Unknown"

        if isinstance(registration_length, int):
            registration_length_text = (
                f"{registration_length} days ({registration_length / 365:.1f} years)"
            )
        else:
            registration_length_text = "Unknown"

        return {
            "domain_age": domain_age_text,
            "registration_length": registration_length_text
        }
    
    except:
        return {
            "domain_age": "Unknown",
            "registration_length": "Unknown"
        }