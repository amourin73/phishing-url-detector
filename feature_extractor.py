import re
from urllib.parse import urlparse
import tldextract
import math


class AdvancedFeatureExtractor:
    def __init__(self):
        self.feature_names = [
            # Basic features
            'url_length', 'num_dots', 'num_hyphens', 'num_underscores',
            'num_slashes', 'num_question_marks', 'num_equals', 'num_ampersands',
            'num_digits', 'num_letters', 'has_https',

            # Domain features
            'domain_length', 'num_subdomains', 'tld_length',

            # Security features
            'has_ip', 'has_at_symbol', 'has_redirect',

            # Service features
            'is_short_url', 'is_suspicious_tld',

            # Content features
            'has_suspicious_words', 'has_brand_names',

            # Statistical features
            'entropy', 'vowel_ratio', 'consonant_ratio', 'digit_ratio',
            'special_char_ratio', 'is_random_looking'
        ]

    def extract(self, url):
        try:
            features = []

            # 1. Basic URL features
            features.append(len(url))
            features.append(url.count('.'))
            features.append(url.count('-'))
            features.append(url.count('_'))
            features.append(url.count('/'))
            features.append(url.count('?'))
            features.append(url.count('='))
            features.append(url.count('&'))
            features.append(sum(c.isdigit() for c in url))
            features.append(sum(c.isalpha() for c in url))
            features.append(1 if url.startswith('https') else 0)

            # 2. Domain analysis
            extracted = tldextract.extract(url)
            features.append(len(extracted.domain))
            features.append(len(extracted.subdomain.split('.')) if extracted.subdomain else 0)
            features.append(len(extracted.suffix))

            # 3. Security features
            features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)
            features.append(1 if '@' in url else 0)
            features.append(1 if '//' in url[7:] else 0)  # Redirect after protocol

            # 4. Service features
            short_services = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'is.gd', 'ow.ly', 'buff.ly']
            features.append(1 if any(service in url for service in short_services) else 0)

            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.gq', '.men', '.work']
            features.append(1 if any(tld in extracted.suffix for tld in suspicious_tlds) else 0)

            # 5. Content features
            suspicious_keywords = [
                'login', 'verify', 'account', 'secure', 'banking', 'update', 'confirm',
                'signin', 'authenticate', 'password', 'wallet', 'crypto', 'bitcoin',
                'validation', 'authorize', 'recovery', 'reset', 'security'
            ]
            features.append(1 if any(keyword in url.lower() for keyword in suspicious_keywords) else 0)

            brands = ['google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal',
                      'netflix', 'instagram', 'twitter', 'whatsapp', 'bank', 'wells', 'chase']
            domain = extracted.domain.lower()
            features.append(1 if any(brand in url.lower() and brand not in domain for brand in brands) else 0)

            # 6. Statistical features
            features.append(self.calculate_entropy(url))
            features.append(self.calculate_vowel_ratio(url))
            features.append(self.calculate_consonant_ratio(url))
            features.append(self.calculate_digit_ratio(url))
            features.append(self.calculate_special_char_ratio(url))
            features.append(self.is_random_looking(extracted.domain))

            return features

        except Exception as e:
            print(f"Error extracting features from {url}: {e}")
            return [0] * len(self.feature_names)

    def calculate_entropy(self, text):
        """Calculate Shannon entropy without numpy"""
        if len(text) <= 1:
            return 0
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p_x = count / len(text)
            entropy += -p_x * math.log2(p_x)
        return entropy

    def calculate_vowel_ratio(self, text):
        vowels = 'aeiouAEIOU'
        vowel_count = sum(1 for char in text if char in vowels)
        return vowel_count / len(text) if text else 0

    def calculate_consonant_ratio(self, text):
        consonants = 'bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ'
        consonant_count = sum(1 for char in text if char in consonants)
        return consonant_count / len(text) if text else 0

    def calculate_digit_ratio(self, text):
        digit_count = sum(1 for char in text if char.isdigit())
        return digit_count / len(text) if text else 0

    def calculate_special_char_ratio(self, text):
        special_chars = '.-_/?=&@'
        special_count = sum(1 for char in text if char in special_chars)
        return special_count / len(text) if text else 0

    def is_random_looking(self, domain):
        """Check if domain looks randomly generated"""
        if len(domain) < 8:
            return 0

        # Check for repeated patterns or unusual character distributions
        entropy = self.calculate_entropy(domain)
        vowel_ratio = self.calculate_vowel_ratio(domain)

        # High entropy and low vowel ratio suggests randomness
        if entropy > 3.5 and vowel_ratio < 0.3:
            return 1
        return 0