import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re
import json
import time
from typing import Dict, List, Tuple
import ollama
from dataclasses import dataclass
from collections import Counter
from datetime import datetime

@dataclass
class WebpageFeatures:
    """Data class to store extracted features from webpage content"""
    title: str
    forms_count: int
    input_fields: List[str]
    suspicious_keywords: List[str]
    popup_indicators: int
    ads_count: int
    suspicious_elements: List[str]
    text_content: str
    meta_description: str
    javascript_suspicious: bool
    iframe_count: int
    hidden_elements: int
    urgency_indicators: int
    social_engineering_signals: List[str]
    form_actions: List[str]
    suspicious_scripts: List[str]

class WebpagePhishingDetector:
    def __init__(self):
        """Initialize the webpage phishing detector with content-based rules"""
        self.suspicious_keywords = [
            'urgent', 'verify', 'suspend', 'update', 'confirm', 'security alert',
            'account blocked', 'click here', 'limited time', 'act now', 'winner',
            'congratulations', 'free money', 'inheritance', 'lottery', 'prize',
            'banking alert', 'paypal', 'amazon security', 'microsoft support',
            'apple id', 'google account', 'facebook security', 'twitter verification',
            'suspended', 'expired', 'immediate action', 'verify identity',
            'claim now', 'tax refund', 'virus detected', 'system infected'
        ]
        
        self.social_engineering_phrases = [
            'verify your account', 'confirm your identity', 'update payment method',
            'suspicious activity', 'unusual activity', 'security breach',
            'account compromised', 'click to verify', 'avoid account suspension',
            'immediate response required', 'act within 24 hours'
        ]
        
        self.urgency_words = [
            'urgent', 'immediately', 'asap', 'expire', 'deadline', 'last chance',
            'limited time', 'hurry', 'quick', 'fast', 'now or never', 'today only'
        ]
        
        self.trusted_domains = {
            "github.com", "youtube.com", "google.com", "gmail.com", 
            "microsoft.com", "apple.com", "facebook.com", "twitter.com",
            "linkedin.com", "stackoverflow.com"
        }
        
        self.suspicious_tlds = {"xyz", "top", "tk", "gq", "cf", "ru", "cn", "bond"}
        # Initialize Ollama client
        self.llm_client = ollama
        
    def scrape_webpage(self, url: str, timeout: int = 10) -> Tuple[BeautifulSoup, requests.Response]:
        """Scrape webpage content and return BeautifulSoup object"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup, response
        except Exception as e:
            print(f"Error scraping {url}: {e}")
            return None, None
    
    def get_domain_reputation(self, url: str) -> Dict[str, float]:
        """Check domain reputation based on trusted domains and suspicious TLDs"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove "www."
        if domain.startswith("www."):
            domain = domain[4:]
        
        reputation_score = 0.5  # neutral baseline (0=trusted, 1=suspicious)
        reputation_reason = []
        
        # Trusted domain → reduce risk
        if any(domain.endswith(td) for td in self.trusted_domains):
            reputation_score = 0.0
            reputation_reason.append("trusted_domain")
        
        # Suspicious TLD → increase risk
        tld = domain.split(".")[-1]
        if tld in self.suspicious_tlds:
            reputation_score = 0.8
            reputation_reason.append("suspicious_tld")
        
        return {
            "domain": domain,
            "tld": tld,
            "reputation_score": reputation_score,
            "reputation_reason": reputation_reason
        }
        
    def extract_webpage_features(self, soup: BeautifulSoup) -> WebpageFeatures:
        """Extract comprehensive features from webpage content only"""
        
        # Basic page info
        title = soup.title.string if soup.title else ""
        meta_desc = ""
        meta_tag = soup.find('meta', attrs={'name': 'description'})
        if meta_tag:
            meta_desc = meta_tag.get('content', '')
        
        # Form analysis - critical for phishing
        forms = soup.find_all('form')
        forms_count = len(forms)
        input_fields = []
        form_actions = []
        
        for form in forms:
            # Get form action
            action = form.get('action', '')
            if action:
                form_actions.append(action)
            
            # Analyze input fields
            inputs = form.find_all('input')
            for inp in inputs:
                input_type = inp.get('type', '').lower()
                input_name = inp.get('name', '').lower()
                input_placeholder = inp.get('placeholder', '').lower()
                input_fields.append(f"{input_type}:{input_name}:{input_placeholder}")
        
        # Get all text content
        text_content = soup.get_text().lower()
        
        # Analyze suspicious keywords
        suspicious_found = [kw for kw in self.suspicious_keywords if kw in text_content]
        
        # Social engineering detection
        social_signals = [phrase for phrase in self.social_engineering_phrases if phrase in text_content]
        
        # Urgency indicators
        urgency_count = sum(1 for word in self.urgency_words if word in text_content)
        
        # Popup and modal detection
        popup_indicators = 0
        popup_indicators += len(soup.find_all(attrs={'onclick': re.compile(r'window\.open|popup|modal', re.I)}))
        popup_indicators += len(soup.find_all('script', string=re.compile(r'alert\(|confirm\(|prompt\(', re.I)))
        popup_indicators += len(soup.find_all(class_=re.compile(r'popup|modal|overlay', re.I)))
        popup_indicators += len(soup.find_all(attrs={'data-toggle': 'modal'}))
        
        # Ads and suspicious content detection
        ads_count = 0
        ads_count += len(soup.find_all(class_=re.compile(r'ad[^a-z]|banner|advertisement|sponsor', re.I)))
        ads_count += len(soup.find_all(id=re.compile(r'ad[^a-z]|banner|advertisement|sponsor', re.I)))
        
        # Iframe analysis (often used in phishing)
        iframe_count = len(soup.find_all('iframe'))
        
        # Hidden elements (suspicious)
        hidden_elements = 0
        hidden_elements += len(soup.find_all(attrs={'style': re.compile(r'display:\s*none|visibility:\s*hidden', re.I)}))
        hidden_elements += len(soup.find_all(attrs={'type': 'hidden'}))
        
        # JavaScript analysis
        js_suspicious = False
        suspicious_scripts = []
        scripts = soup.find_all('script')
        
        for script in scripts:
            script_content = script.string or ""
            script_src = script.get('src', '')
            
            # Check for suspicious JavaScript patterns
            suspicious_js_patterns = [
                'eval(', 'document.write', 'unescape', 'fromcharcode',
                'atob(', 'btoa(', 'innerhtml', 'location.href',
                'window.location', 'document.cookie', 'base64'
            ]
            
            for pattern in suspicious_js_patterns:
                if pattern in script_content.lower() or pattern in script_src.lower():
                    js_suspicious = True
                    suspicious_scripts.append(pattern)
                    break
        
        # Analyze suspicious page elements
        suspicious_elements = []
        
        # Check for password fields (high risk in phishing)
        password_fields = soup.find_all('input', {'type': 'password'})
        if password_fields:
            suspicious_elements.append(f'password_fields:{len(password_fields)}')
        
        # Check for sensitive data requests
        sensitive_patterns = [
            r'social security|ssn|social security number',
            r'credit card|card number|cvv|cvc|expiry',
            r'bank account|routing number|account number',
            r'driver.?license|license number',
            r'passport|passport number'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, text_content, re.I):
                suspicious_elements.append(f'sensitive_data_request:{pattern}')
        
        # Check for multiple forms (red flag)
        if forms_count > 2:
            suspicious_elements.append(f'multiple_forms:{forms_count}')
        
        # Check for fake security badges/logos
        security_images = soup.find_all('img', src=re.compile(r'security|secure|ssl|verified|badge', re.I))
        if len(security_images) > 3:
            suspicious_elements.append(f'excessive_security_badges:{len(security_images)}')
        
        # Check for countdown timers (urgency tactic)
        if re.search(r'countdown|timer|expires?.*\d|time.*left', text_content, re.I):
            suspicious_elements.append('countdown_timer')
        
        # Check for fake error messages
        if re.search(r'error.*occurred|something.*wrong|try.*again|failed.*login', text_content, re.I):
            suspicious_elements.append('fake_error_messages')
        
        return WebpageFeatures(
            title=title,
            forms_count=forms_count,
            input_fields=input_fields,
            suspicious_keywords=suspicious_found,
            popup_indicators=popup_indicators,
            ads_count=ads_count,
            suspicious_elements=suspicious_elements,
            text_content=text_content[:2000],  # Limit for LLM
            meta_description=meta_desc,
            javascript_suspicious=js_suspicious,
            iframe_count=iframe_count,
            hidden_elements=hidden_elements,
            urgency_indicators=urgency_count,
            social_engineering_signals=social_signals,
            form_actions=form_actions,
            suspicious_scripts=list(set(suspicious_scripts))  # Remove duplicates
        )
    
    def calculate_content_risk_score(self, features: WebpageFeatures) -> Dict[str, float]:
        """Calculate risk score based purely on webpage content analysis with higher weightage"""
        risk_score = 0.0
        risk_factors = {}
        
        # Forms (higher risk now)
        if features.forms_count > 0:
            form_risk = min(features.forms_count * 0.35, 0.7)
            risk_factors['forms_present'] = form_risk
            risk_score += form_risk
        
        # Password fields (very high)
        password_fields = [field for field in features.input_fields if 'password' in field]
        if password_fields:
            risk_factors['password_fields'] = 0.6
            risk_score += risk_factors['password_fields']
        
        # Suspicious keywords
        if features.suspicious_keywords:
            keyword_risk = min(len(features.suspicious_keywords) * 0.15, 0.6)
            risk_factors['suspicious_keywords'] = keyword_risk
            risk_score += keyword_risk
        
        # Social engineering
        if features.social_engineering_signals:
            social_risk = min(len(features.social_engineering_signals) * 0.25, 0.7)
            risk_factors['social_engineering'] = social_risk
            risk_score += social_risk
        
        # Urgency indicators
        if features.urgency_indicators > 0:
            urgency_risk = min(features.urgency_indicators * 0.2, 0.5)
            risk_factors['urgency_tactics'] = urgency_risk
            risk_score += urgency_risk
        
        # JavaScript suspicious
        if features.javascript_suspicious:
            risk_factors['suspicious_javascript'] = 0.2
            risk_score += risk_factors['suspicious_javascript']
        
        # Popups
        if features.popup_indicators > 0:
            popup_risk = min(features.popup_indicators * 0.25, 0.5)
            risk_factors['popups'] = popup_risk
            risk_score += popup_risk
        
        # Hidden elements
        if features.hidden_elements > 5:
            hidden_risk = min((features.hidden_elements - 5) * 0.1, 0.4)
            risk_factors['hidden_elements'] = hidden_risk
            risk_score += hidden_risk
        
        # Iframes
        if features.iframe_count > 0:
            iframe_risk = min(features.iframe_count * 0.1, 0.2)
            risk_factors['iframes'] = iframe_risk
            risk_score += iframe_risk
        
        # Ads
        if features.ads_count > 5:
            ad_risk = min((features.ads_count - 5) * 0.06, 0.2)
            risk_factors['excessive_ads'] = ad_risk
            risk_score += ad_risk
        
        # Suspicious elements
        if features.suspicious_elements:
            element_risk = min(len(features.suspicious_elements) * 0.2, 0.6)
            risk_factors['suspicious_elements'] = element_risk
            risk_score += element_risk
        
        return {
            'total_risk_score': min(risk_score, 1.0),
            'risk_factors': risk_factors
        }


    
    def analyze_content_with_llm(self, features: WebpageFeatures) -> Dict[str, any]:
        """Use Mistral LLM to analyze webpage content for phishing indicators"""
        
        # Construct detailed prompt focusing on content analysis
        prompt = f"""
        Analyze this webpage content for phishing indicators. Focus on content, structure, and user interaction patterns.

        WEBPAGE CONTENT ANALYSIS:
        Title: {features.title}
        Meta Description: {features.meta_description}
        
        FORMS & INTERACTIONS:
        - Number of forms: {features.forms_count}
        - Input fields: {', '.join(features.input_fields[:15])}
        - Form actions: {', '.join(features.form_actions[:5])}
        
        CONTENT SIGNALS:
        - Suspicious keywords: {', '.join(features.suspicious_keywords)}
        - Social engineering signals: {', '.join(features.social_engineering_signals)}
        - Urgency indicators: {features.urgency_indicators}
        
        TECHNICAL ELEMENTS:
        - Popups/Modals: {features.popup_indicators}
        - Hidden elements: {features.hidden_elements}
        - Iframes: {features.iframe_count}
        - Suspicious scripts: {', '.join(features.suspicious_scripts)}
        - Suspicious page elements: {', '.join(features.suspicious_elements)}
        
        CONTENT SAMPLE:
        {features.text_content[:1500]}
        
        Analyze for phishing based on:
        1. Content manipulation tactics
        2. Social engineering attempts
        3. Suspicious form requests
        4. Urgency/pressure tactics
        5. Technical red flags
        
        Respond ONLY with valid JSON:
        {{
            "phishing_likelihood": <0-100>,
            "content_red_flags": ["flag1", "flag2", ...],
            "confidence": <0-100>,
            "primary_tactics": ["tactic1", "tactic2", ...],
            "reasoning": "detailed explanation focusing on content analysis"
        }}
        """
        
        try:
            response = self.llm_client.generate(
                model='mistral',
                prompt=prompt,
                options={
                    'temperature': 0.2,
                    'top_p': 0.8,
                    'max_tokens': 600
                }
            )
            
            # Extract JSON from response
            response_text = response['response'].strip()
            
            # Find JSON in response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_text = response_text[json_start:json_end]
                llm_analysis = json.loads(json_text)
                return llm_analysis
            else:
                return {
                    "phishing_likelihood": 50,
                    "content_red_flags": ["LLM parsing failed"],
                    "confidence": 0,
                    "primary_tactics": [],
                    "reasoning": "Could not parse LLM response"
                }
                
        except Exception as e:
            print(f"LLM analysis error: {e}")
            return {
                "phishing_likelihood": 50,
                "content_red_flags": [f"LLM error: {str(e)}"],
                "confidence": 0,
                "primary_tactics": [],
                "reasoning": "LLM analysis failed"
            }
    
    def detect_webpage_phishing(self, url: str) -> Dict[str, any]:
        """Main method to detect phishing based purely on webpage content + domain reputation"""
        
        print(f"Analyzing webpage content: {url}")
        
        # Step 0: Domain reputation check
        domain_reputation = self.get_domain_reputation(url)
        
        # Step 1: Scrape webpage
        soup, response = self.scrape_webpage(url)
        if not soup or not response:
            return {
                "url": url,
                "error": "Failed to scrape webpage",
                "is_phishing": False,
                "confidence": 0
            }
        
        # Step 2: Extract content features
        features = self.extract_webpage_features(soup)
        
        # Step 3: Calculate content-based risk score
        content_analysis = self.calculate_content_risk_score(features)
        
        # Step 4: LLM content analysis
        print("Running LLM content analysis...")
        llm_analysis = self.analyze_content_with_llm(features)
        
        # Step 5: Combine content-based results
        content_score = content_analysis['total_risk_score']
        llm_score = llm_analysis['phishing_likelihood'] / 100.0
        combined_score = (content_score * 0.50) + (llm_score * 0.50)
        
        # Step 6: Adjust with domain reputation
        if domain_reputation["reputation_score"] == 0.0:
            # Trusted → cap score
            combined_score = min(combined_score, 0.2)
        elif domain_reputation["reputation_score"] >= 0.8:
            # Suspicious TLD → boost score
            combined_score = min(combined_score + 0.2, 1.0)
        
        # Step 7: Final decision
        is_phishing = combined_score > 0.5
        confidence = min(abs(combined_score - 0.5) * 2, 1.0) * 100
        
        return {
            "url": url,
            "is_phishing": is_phishing,
            "confidence": confidence,
            "combined_risk_score": combined_score,
            "domain_reputation": domain_reputation,
            "content_analysis": content_analysis,
            "llm_analysis": llm_analysis,
            "webpage_features": {
                "title": features.title,
                "forms_count": features.forms_count,
                "input_fields_sample": features.input_fields[:10],
                "suspicious_keywords": features.suspicious_keywords,
                "social_engineering_signals": features.social_engineering_signals,
                "popup_indicators": features.popup_indicators,
                "ads_count": features.ads_count,
                "iframe_count": features.iframe_count,
                "hidden_elements": features.hidden_elements,
                "urgency_indicators": features.urgency_indicators,
                "suspicious_elements": features.suspicious_elements,
                "javascript_suspicious": features.javascript_suspicious,
                "suspicious_scripts": features.suspicious_scripts
            },
            "timestamp": datetime.now().isoformat()
        }

def main():
    """Example usage of the webpage content phishing detector"""
    
    detector = WebpagePhishingDetector()
    
    # Test URLs (replace with actual URLs to test)
    test_urls = [
        "https://github.com/SSanjay0614",
        "https://www.youtube.com/",
        "https://www.5movierulz.villas/",
        "https://watchserieshd.bond/",
        "https://unblocked-games.s3.amazonaws.com/index.html"
    ]
    
    results = []
    
    for url in test_urls:
        try:
            result = detector.detect_webpage_phishing(url)
            results.append(result)
            
            print(f"\n{'='*60}")
            print(f"WEBPAGE CONTENT ANALYSIS")
            print(f"URL: {result['url']}")
            print(f"Is Phishing: {result['is_phishing']}")
            print(f"Confidence: {result['confidence']:.1f}%")
            print(f"Combined Risk Score: {result['combined_risk_score']:.3f}")
            print(f"Content Score: {result['content_analysis']['total_risk_score']:.3f}")
            print(f"LLM Score: {result['llm_analysis']['phishing_likelihood']}/100")
            
            print(f"\nContent Red Flags: {', '.join(result['llm_analysis']['content_red_flags'])}")
            print(f"Primary Tactics: {', '.join(result['llm_analysis'].get('primary_tactics', []))}")
            
            features = result['webpage_features']
            print(f"\nWebpage Features:")
            print(f"  - Forms: {features['forms_count']}")
            print(f"  - Suspicious Keywords: {len(features['suspicious_keywords'])}")
            print(f"  - Social Engineering: {len(features['social_engineering_signals'])}")
            print(f"  - Popups: {features['popup_indicators']}")
            print(f"  - Suspicious Elements: {len(features['suspicious_elements'])}")
            
            if result['content_analysis']['risk_factors']:
                print("\nContent Risk Factors:")
                for factor, score in result['content_analysis']['risk_factors'].items():
                    print(f"  - {factor}: {score:.3f}")
                    
        except Exception as e:
            print(f"Error analyzing {url}: {e}")
            
        time.sleep(1)  # Be respectful to servers
    
    # Save results
    with open('webpage_phishing_analysis.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nWebpage content analysis complete! Results saved to webpage_phishing_analysis.json")

if __name__ == "__main__":
    main()