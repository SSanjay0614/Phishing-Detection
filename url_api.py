import re
import pandas as pd
import joblib
import tldextract
from fastapi import FastAPI
from pydantic import BaseModel

# -----------------
# Pydantic Model for API Input
# -----------------
class URLInput(BaseModel):
    url: str

# -----------------
# Core Functions
# -----------------
suspicious_keywords = {
    "login": ["login", "signin", "account"],
    "secure": ["secure", "verify", "update"],
    "bank": ["bank", "paypal", "chase", "wellsfargo"],
    "payment": ["payment", "billing", "invoice"],
    "support": ["support", "helpdesk"]
}

# This function must be defined BEFORE extract_url_features
def add_keyword_features(url, features_dict):
    domain_path = url.lower()
    total_suspicious = 0
    for key, keywords in suspicious_keywords.items():
        features_dict[f"has_{key}"] = int(any(k in domain_path for k in keywords))
        if features_dict[f"has_{key}"]:
            total_suspicious += 1
    features_dict["num_suspicious_keywords"] = total_suspicious
    return features_dict

KNOWN_TLDS = ['com', 'jp', 'site', 'org', 'gd', 'my', 'no', 'me', 'id', 'edu', 'io', 'app', 'de', 'in', 'nz', 'au', 'info', 'cl', 'nl', 'ru', 'net', 'eu', 'pl', 'uk', 'co', 'ca', 'kr', 'ch', 'kim', 'cloud', 'ge', 'cards', 'cf', 'club', 'link', 'fr', 'one', 'us', 'se', 'ro', 'xyz', 'am', 'art', 'hr', 'fun', 'it', 'plus', 'gov', 'ga', 'fm', 'vn', 'gal', 'top', 'sg', 'dev', 'digital', 'za', 'tv', 'es', 'fi', 'ar', 'at', 'tr', 'cz', 'dk', 'be', 'watch', 'video', 'az', 'fit', 'biz', 'pk', 'cn', 'to', 'br', 'uz', 'cc', 'ir', 'coop', 'li', 'pe', '238', 'ie', 'bg', 'business', 'ws', 'hu', 'mil', 'cyou', 'shop', 'uno', 'zw', 'host', '146', 'gr', 'ua', 'sc', 'ht', 'pro', 'pw', 'mobi', 'sh', 'pt', 'kz', 'land', 'hk', 'ma', 've', 'th', 'rs', 'ee', 'ml', 'ae', 'il', 'bd', 'online', '232', 'pet', 'ug', 'is', 'nyc', 'nf', 'ng', 'al', 'page', 'tokyo', 'network', '67', 'gy', 'space', 'bid', 'bio', 'world', 'gp', 'do', 'by', 'email', 'website', 'asia', 'work', 'tw', 'si', 'pg', 'lk', 'tech', 'hn', 'lv', 'guru', 'travel', 'mx', 'ec', 'store', 'mn', 'tk', 'services', 'st', 'na', 'uy', 'name', 'ph', '181', '178', 'place', 'im', 'date', 'gq', 'mm', 'live', 'lc', 'center', '41', 'life', 'expert', 'gi', 'vip', 'icu', 'mv', 'nu', 'su', 'gle', 'np', 'cfd', '86', 'media', 'jo', 'lu', 'zone', 'sa', 're', 'lt', 'news', '69', 'school', 'ly', 'ke', 'church', 'la', 'xn--p1ai', 'lol', '24', 'sport', 'fyi', 'institute', 'lighting', 'navy', 'gg', 'mq', 'cy', 'swiss', 'ai', 'exchange', 'sk', '136', 'studio', 'mom', 'bw', 'sbs', 'tn', '128', 'cat', 'bo', 'bz', 'pics', 'mz', 'win', 'tz', 'market', 'int', 'dz', 'je', 'pm', 'company', 'law', 'ink', 'mk', 'museum', 'party', 'ngo', 'ba', 'eg', '154', 'bank', '103', 'science', 'jm', 'vg', 'technology', 'iq', 'qa', 'so', 'stream', 'cool', 'tl', 'monster', 'bf', 'academy', 'cx', 'fashion', 'games', 'buzz', 'tc', 'bar', '87', 'xn--p1acf', 'ltd', 'money', 'best', '21', 'ss', 'computer', 'eus', 'fj', '42', 'cash', '26', 'quest', 'berlin', 'py', 'mg', 'cr', 'bet', 'lb', 'bt', 'bh', 'vote', 'land:443', 'fund', 'global', 'scot', 'ax', 'systems', 'fk', 'goog', '234', '20', 'bb', 'casa', 'kg', 'archi', 'com:2096', '120', 'tt', 'health', 'solutions', 'xn--6frz82g', 'wales', 'mt', 'tm', 'love', 'ad', 'gl', 'cam', 'af', 'guide', 'click', '252', 'farm', 'wiki', 'lr', 'ac', '116', 'green', 'group', 'ls', 'mp', '78', 'cu', 'vu', 'red', 'finance', 'today', '94', 'gt', 'cm', 'blog', 'vc', 'tips', 'skin', 'bm', 'care', '150', 'college', 'ps', 'auto', 'gf', 'ovh', 'photo', 'tools', 'marketing', 'kh', 'sv', 'mu', 'ci', '80', 'aero', 'rest', 'supply', 'tg', '197', 'md', 'social', 'hair', 'run', '130', 'build', 'aw', 'ao', '223', 'hamburg', 'homes', 'pink', 'cars', '133:8080', 'design', 'nagoya', 'om', 'cd', 'basketball', 'trade', 'ms', 'gh', '171', 'garden', 'mba', 'paris', 'report', '189', 'google', 'investments', 'africa', '101', 'events', 'moe', 'soy', 'yt', 'rw', '28', 'coach', 'domains', 'ist', 'zm', 'team', 'pn', 'pl:443', 'london', 'review', 'fo', 'krd', 'wine', 'kn', 'tj', 'as', '15', 'holdings', '95', '12', 'autos', '158', 'beauty', '11', 'photos', '148', 'gives', '140', 'bn', '30', 'pa', '13', 'ky', 'ooo', 'mc', 'sd', '68:8080', 'mw', '123', 'rocks', 'rentals', '211', 'lgbt', '126', 'amsterdam', 'kw', 'sn', 'chat', 'band', 'agency', 'istanbul', 'house', 'camera', 'markets', 'gdn', 'nc', '231', 'boutique', '242', 'bi', 'yachts', 'com:443', '38', 'dj', 'camp', '108', 'cymru', '200', 'download', 'vegas', 'works', 'photography', 'foundation', 'press', 'dog', '188:10003', 'hosting', 'dm', 'game', 'toys', 'city', 'ne', 'bike', 'com:9595', 'menu', 'bs', 'sb', '106', '230', 'car', 'reviews', 'wf', 'koeln', 'golf', 'wtf', 'sm', 'tf', 'sy', 'limo', 'cafe', 'vet', '240:8087', 'gifts', '117', 'tours', 'tel', 'cv', 'ni', 'gs', 'taxi', '185', '210', '220', 'education', '237', 'bj', 'capital', 'diamonds', 'vi', 'tattoo', '250', '199', '155', 'dental', 'sx', 'careers', 'support', '235', 'eco', 'ag', 'loan', '100', 'radio', 'coffee', 'delivery', 'xn--mk1bu44c', 'show', 'ninja', 'rugby', '149', '214', '47', '173', 'fitness', 'sr', 'gallery', 'gay', 'help', 'moscow', 'pf', 'pub', 'ski', '206', '254:30332', 'jobs', '198', 'rip', 'earth', '134', 'holiday', '166', 'corsica', 'limited', 'salon', 'gold', 'audio', '51', 'xn--90ais', '126:8080', 'mma', 'tirol', '187', 'shoes', '111', 'nr', 'promo', 'energy', '52', '182', 'youtube', 'sexy', 'mo', 'sz', '184', 'engineering', 'aq', 'parts', '196', 'lat', 'express', '233', 'ruhr', '121', 'builders', '71', 'recipes', 'mr', '43', 'family', '161', 'madrid', 'movie', 'community', 'fr:443', 'repair', '151', '160', 'study', '110', 'consulting', 'direct', '163', 'furniture', 'cc:8443', '107', 'associates', 'beer', '167', '33', 'clothing', 'bayern', '46', 'schule', 'ck', 'tatar', '221', '227', 'town', 'kiwi', 'training', 'nrw', 'vlaanderen', 'theater', '203', 'et', '63', 'gmbh', '211:8383', 'black', '243', 'lundbeck', '177', 'kred', 'ki', 'legal', 'com:4000', 'yoga', '145', '125', 'xn--c1avg', '80:8085', '84', 'barcelona', 'sharp', '216', 'tax', '225', 'software', 'kitchen', 'healthcare', 'neustar', 'ntt', 'mortgage', 'taipei', 'faith', 'management', 'international', 'condos', 'cleaning', 'maison']

def extract_url_features(url, known_tlds=None):
    if known_tlds is None:
        known_tlds = {"com", "org", "net", "gov", "co.uk", "info", "io"}

    original_url = url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    ext = tldextract.extract(url)
    domain = ext.domain
    subdomain = ext.subdomain
    tld = ext.suffix if ext.suffix in known_tlds else "unknown"

    url_length = len(original_url)
    domain_full = f"{subdomain}.{domain}.{tld}" if subdomain else f"{domain}.{tld}"
    domain_length = len(domain_full)
    is_domain_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0
    tld_length = len(tld)
    no_of_subdomain = len([s for s in subdomain.split('.') if s]) if subdomain else 0
    has_obfuscation = 0
    no_of_obfuscated = 0
    obfuscation_ratio = 0.0
    letters = sum(c.isalpha() for c in domain)
    letter_ratio = letters / url_length if url_length > 0 else 0
    digits = sum(c.isdigit() for c in original_url)
    digit_ratio = digits / url_length if url_length > 0 else 0
    no_of_equals = original_url.count("=")
    no_of_qmark = original_url.count("?")
    no_of_amp = original_url.count("&")
    no_of_other_special = original_url.count("/")
    spacial_char_ratio = no_of_other_special / url_length if url_length > 0 else 0
    is_https = 1 if original_url.lower().startswith("https://") else 0

    features = {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "TLD": tld,
        "TLDLength": tld_length,
        "NoOfSubDomain": no_of_subdomain,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": no_of_obfuscated,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": no_of_equals,
        "NoOfQMarkInURL": no_of_qmark,
        "NoOfAmpersandInURL": no_of_amp,
        "NoOfOtherSpecialCharsInURL": no_of_other_special,
        "SpacialCharRatioInURL": spacial_char_ratio,
        "IsHTTPS": is_https
    }
    
    # Correctly add keyword features
    features = add_keyword_features(original_url, features)

    # This part needs to create a DataFrame that exactly matches the training data columns
    # and their order. The error you're getting is very specific about a missing TLD column.
    # The fix is to ensure the column is present and in the correct data type (object/string for a categorical).
    
    final_features_dict = {
        "URLLength": features["URLLength"],
        "DomainLength": features["DomainLength"],
        "IsDomainIP": features["IsDomainIP"],
        "TLD": features["TLD"],
        "TLDLength": features["TLDLength"],
        "NoOfSubDomain": features["NoOfSubDomain"],
        "HasObfuscation": features["HasObfuscation"],
        "NoOfObfuscatedChar": features["NoOfObfuscatedChar"],
        "ObfuscationRatio": features["ObfuscationRatio"],
        "NoOfLettersInURL": features["NoOfLettersInURL"],
        "LetterRatioInURL": features["LetterRatioInURL"],
        "NoOfDegitsInURL": features["NoOfDegitsInURL"],
        "DegitRatioInURL": features["DegitRatioInURL"],
        "NoOfEqualsInURL": features["NoOfEqualsInURL"],
        "NoOfQMarkInURL": features["NoOfQMarkInURL"],
        "NoOfAmpersandInURL": features["NoOfAmpersandInURL"],
        "NoOfOtherSpecialCharsInURL": features["NoOfOtherSpecialCharsInURL"],
        "SpacialCharRatioInURL": features["SpacialCharRatioInURL"],
        "IsHTTPS": features["IsHTTPS"],
        "HasTitle": 0,
        "Title": "",
        "DomainTitleMatchScore": 0,
        "URLTitleMatchScore": 0,
        "HasFavicon": 0,
        "Robots": 0,
        "IsResponsive": 0,
        "NoOfURLRedirect": 0,
        "NoOfSelfRedirect": 0,
        "HasDescription": 0,
        "NoOfPopup": 0,
        "NoOfiFrame": 0,
        "HasExternalFormSubmit": 0,
        "HasSocialNet": 0,
        "HasSubmitButton": 0,
        "HasHiddenFields": 0,
        "HasPasswordField": 0,
        "Bank": 0,
        "Pay": 0,
        "Crypto": 0,
        "HasCopyrightInfo": 0,
        "NoOfImage": 0,
        "NoOfCSS": 0,
        "NoOfJS": 0,
        "NoOfSelfRef": 0,
        "NoOfEmptyRef": 0,
        "NoOfExternalRef": 0,
        "has_login": features["has_login"],
        "has_secure": features["has_secure"],
        "has_bank": features["has_bank"],
        "has_payment": features["has_payment"],
        "has_support": features["has_support"],
        "num_suspicious_keywords": features["num_suspicious_keywords"]
    }

    # Creating a DataFrame from a dictionary of lists to ensure all columns are present.
    # We will exclude 'label' as it's not an input feature.
    feature_columns = [
        'URLLength', 'DomainLength', 'IsDomainIP', 'TLD', 'TLDLength', 'NoOfSubDomain', 
        'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio', 'NoOfLettersInURL', 
        'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfEqualsInURL', 
        'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL', 
        'SpacialCharRatioInURL', 'IsHTTPS', 'HasTitle', 'Title', 'DomainTitleMatchScore', 
        'URLTitleMatchScore', 'HasFavicon', 'Robots', 'IsResponsive', 'NoOfURLRedirect', 
        'NoOfSelfRedirect', 'HasDescription', 'NoOfPopup', 'NoOfiFrame', 
        'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton', 'HasHiddenFields', 
        'HasPasswordField', 'Bank', 'Pay', 'Crypto', 'HasCopyrightInfo', 'NoOfImage', 
        'NoOfCSS', 'NoOfJS', 'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfExternalRef', 
        'has_login', 'has_secure', 'has_bank', 'has_payment', 'has_support', 
        'num_suspicious_keywords'
    ]

    all_features = pd.DataFrame([final_features_dict])
    all_features = all_features.reindex(columns=feature_columns, fill_value=0)

    # Ensure the 'TLD' column has the correct data type. This is a common point of failure.
    all_features['TLD'] = all_features['TLD'].astype('object')
    
    return all_features

def compute_heuristic_risk(url, known_tlds, base_prob):
    ext = tldextract.extract(url)
    tld = ext.suffix if ext.suffix in known_tlds else "unknown"
    risk = base_prob
    if tld == "unknown":
        risk += 0.6
    
    url_lower = url.lower()
    keyword_count = sum(1 for kws in suspicious_keywords.values() for k in kws if k in url_lower)
    
    risk += 0.3 * keyword_count
    risk = min(risk, 1.0)
    return risk

# -----------------
# FastAPI Application
# -----------------
app = FastAPI()

# Load the model on startup
model = joblib.load("stacking_url_model.pkl")

@app.post("/predict/")
async def predict_phishing(data: URLInput):
    """
    Receives a URL, extracts features, predicts phishing status, and returns a risk score.
    """
    url = data.url
    
    # 1. Extract features
    try:
        X_new = extract_url_features(url, KNOWN_TLDS)
    except Exception as e:
        return {"error": f"Feature extraction failed: {e}"}

    # 2. Predict using the model
    try:
        base_prob = model.predict_proba(X_new)[:, 1][0]
        prediction = model.predict(X_new)[0]
    except Exception as e:
        return {"error": f"Model prediction failed: {e}"}

    # 3. Calculate heuristic risk score
    final_prob = compute_heuristic_risk(url, KNOWN_TLDS, base_prob)
    risk_score_100 = round(final_prob * 100, 2)

    # 4. Determine final classification
    final_prediction = 1 if final_prob >= 0.5 else 0

    return {
        "url": url,
        "prediction": int(final_prediction),
        "phishing_probability": round(final_prob, 4),
        "risk_score": risk_score_100
    }