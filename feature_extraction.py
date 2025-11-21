"""
Phishing URL Feature Extraction Module
This module extracts 20+ features from URLs to detect phishing attempts
"""

import re
import urllib.parse
from urllib.parse import urlparse
import tldextract
import pandas as pd
import numpy as np

class URLFeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    def __init__(self):
        # Suspicious keywords commonly used in phishing
        self.suspicious_keywords = [
            'verify', 'account', 'secure', 'update', 'login', 
            'banking', 'confirm', 'signin', 'ebayisapi', 'webscr',
            'password', 'credential', 'suspend', 'restricted', 'verify',
            'click', 'urgent', 'expire', 'suspended'
        ]
        
        # URL shortening services
        self.shortening_services = [
            'bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 
            'ow.ly', 't.co', 'tinyurl', 'tr.im', 'is.gd', 'cli.gs',
            'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu',
            'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to'
        ]
    
    def extract_all_features(self, url):
        """
        Extract all features from a single URL
        Returns: Dictionary of features
        """
        try:
            features = {}
            
            # Basic parsing
            parsed = urlparse(url)
            ext = tldextract.extract(url)
            
            # 1. URL LENGTH FEATURES
            features['url_length'] = len(url)
            features['hostname_length'] = len(parsed.netloc)
            features['path_length'] = len(parsed.path)
            features['query_length'] = len(parsed.query)
            
            # 2. CHARACTER COUNT FEATURES
            features['dot_count'] = url.count('.')
            features['hyphen_count'] = url.count('-')
            features['underscore_count'] = url.count('_')
            features['slash_count'] = url.count('/')
            features['questionmark_count'] = url.count('?')
            features['equal_count'] = url.count('=')
            features['at_count'] = url.count('@')
            features['ampersand_count'] = url.count('&')
            features['exclamation_count'] = url.count('!')
            features['space_count'] = url.count(' ')
            features['tilde_count'] = url.count('~')
            features['comma_count'] = url.count(',')
            features['plus_count'] = url.count('+')
            features['asterisk_count'] = url.count('*')
            features['hashtag_count'] = url.count('#')
            features['dollar_count'] = url.count('$')
            features['percent_count'] = url.count('%')
            
            # 3. SUBDOMAIN FEATURES
            subdomains = ext.subdomain.split('.') if ext.subdomain else []
            features['subdomain_count'] = len([s for s in subdomains if s])
            
            # 4. DOMAIN FEATURES
            domain = ext.domain
            features['domain_length'] = len(domain)
            features['domain_digit_count'] = sum(c.isdigit() for c in domain)
            features['domain_digit_ratio'] = features['domain_digit_count'] / max(len(domain), 1)
            
            # 5. PROTOCOL FEATURES
            features['is_https'] = 1 if parsed.scheme == 'https' else 0
            features['is_http'] = 1 if parsed.scheme == 'http' else 0
            
            # 6. IP ADDRESS DETECTION
            features['has_ip'] = self._has_ip_address(parsed.netloc)
            
            # 7. SUSPICIOUS KEYWORDS
            url_lower = url.lower()
            keyword_count = sum(1 for keyword in self.suspicious_keywords if keyword in url_lower)
            features['suspicious_keyword_count'] = keyword_count
            features['has_suspicious_keywords'] = 1 if keyword_count > 0 else 0
            
            # 8. URL SHORTENING SERVICE
            features['is_shortened'] = 1 if any(service in url_lower for service in self.shortening_services) else 0
            
            # 9. DOUBLE SLASH IN PATH
            features['double_slash_in_path'] = 1 if '//' in parsed.path else 0
            
            # 10. PREFIX/SUFFIX IN DOMAIN
            features['has_prefix_suffix'] = 1 if '-' in domain else 0
            
            # 11. SPECIAL CHARACTER RATIOS
            special_chars = sum(1 for c in url if not c.isalnum())
            features['special_char_ratio'] = special_chars / max(len(url), 1)
            
            # 12. DIGIT RATIO IN URL
            digit_count = sum(c.isdigit() for c in url)
            features['digit_ratio'] = digit_count / max(len(url), 1)
            
            # 13. LETTER RATIO IN URL
            letter_count = sum(c.isalpha() for c in url)
            features['letter_ratio'] = letter_count / max(len(url), 1)
            
            # 14. TLD LENGTH
            features['tld_length'] = len(ext.suffix)
            
            # 15. ENTROPY (measure of randomness)
            features['entropy'] = self._calculate_entropy(url)
            
            # 16. CONSECUTIVE CONSONANTS (can indicate random generated domains)
            features['max_consecutive_consonants'] = self._max_consecutive_consonants(domain)
            
            # 17. VOWEL RATIO IN DOMAIN
            vowels = 'aeiou'
            vowel_count = sum(1 for c in domain.lower() if c in vowels)
            features['vowel_ratio'] = vowel_count / max(len(domain), 1)
            
            # 18. HEX CHARACTERS (obfuscation technique)
            features['has_hex'] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
            
            # 19. PUNYCODE (internationalized domains)
            features['is_punycode'] = 1 if 'xn--' in url.lower() else 0
            
            # 20. PORT NUMBER
            features['has_port'] = 1 if ':' in parsed.netloc and parsed.port else 0
            
            return features
            
        except Exception as e:
            print(f"Error extracting features from {url}: {str(e)}")
            return None
    
    def _has_ip_address(self, netloc):
        """Check if URL contains IP address instead of domain name"""
        # IPv4 pattern
        ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        
        # Remove port if present
        host = netloc.split(':')[0]
        
        # Check IPv4
        if ipv4_pattern.match(host):
            return 1
        
        # Check IPv6 (simplified)
        if '[' in host and ']' in host:
            return 1
        
        return 0
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        # Calculate frequency of each character
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        text_len = len(text)
        for count in freq.values():
            probability = count / text_len
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _max_consecutive_consonants(self, text):
        """Find maximum consecutive consonants in text"""
        consonants = 'bcdfghjklmnpqrstvwxyz'
        max_count = 0
        current_count = 0
        
        for char in text.lower():
            if char in consonants:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        
        return max_count
    
    def extract_features_from_dataframe(self, df, url_column='url'):
        """
        Extract features for all URLs in a dataframe
        
        Args:
            df: DataFrame with URLs
            url_column: Name of column containing URLs
        
        Returns:
            DataFrame with all features
        """
        print(f"Extracting features from {len(df)} URLs...")
        
        feature_list = []
        
        for idx, url in enumerate(df[url_column]):
            if idx % 1000 == 0:
                print(f"Processed {idx}/{len(df)} URLs...")
            
            features = self.extract_all_features(url)
            if features:
                feature_list.append(features)
            else:
                # If feature extraction fails, add None values
                feature_list.append({})
        
        # Convert to DataFrame
        features_df = pd.DataFrame(feature_list)
        
        # Add original URL and label (if exists)
        features_df['url'] = df[url_column].values
        if 'label' in df.columns:
            features_df['label'] = df['label'].values
        
        print(f"Feature extraction complete! Shape: {features_df.shape}")
        
        return features_df


# Example usage
if __name__ == "__main__":
    # Test with sample URLs
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login.php",
        "http://secure-paypal-login.verification-required.com/update-account",
        "https://bit.ly/xyz123",
        "http://amazon-security-alert.com/verify-account?user=12345"
    ]
    
    extractor = URLFeatureExtractor()
    
    print("Testing feature extraction on sample URLs:\n")
    for url in test_urls:
        print(f"\nURL: {url}")
        features = extractor.extract_all_features(url)
        
        if features:
            # Print some key features
            print(f"  Length: {features['url_length']}")
            print(f"  HTTPS: {features['is_https']}")
            print(f"  Has IP: {features['has_ip']}")
            print(f"  Suspicious keywords: {features['suspicious_keyword_count']}")
            print(f"  Is shortened: {features['is_shortened']}")
            print(f"  Entropy: {features['entropy']:.2f}")