import re
from .base_rule import BaseRule
from config.settings import Settings

class SuspiciousLinksRule(BaseRule):
    def __init__(self):
        self.settings = Settings()
        # Pre-compile regex patterns for better performance
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        
    def check(self, email: dict) -> bool:
        """
        Check for suspicious links in the email body and subject.
        Returns True if any suspicious links are found.
        """
        # Check both body and subject for URLs
        text_to_check = f"{email.get('subject', '')} {email.get('body', '')}"
        urls = self.url_pattern.findall(text_to_check)
        
        # Check for suspicious domains in URLs
        suspicious_domains = self.settings.get_setting('suspicious_domains')
        for url in urls:
            if self._is_suspicious_url(url, suspicious_domains):
                return True
        
        # Check for common phishing URL patterns
        phishing_patterns = self.settings.get_setting('phishing_url_patterns')
        for pattern in phishing_patterns:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return True
                
        return False
    
    def _is_suspicious_url(self, url: str, suspicious_domains: list) -> bool:
        """Check if a URL contains any suspicious domains or patterns."""
        # Convert to lowercase for case-insensitive comparison
        url_lower = url.lower()
        
        # Check for IP addresses (often used in phishing)
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
            return True
            
        # Check for suspicious domains
        for domain in suspicious_domains:
            if domain.lower() in url_lower:
                return True
                
        # Check for URL shorteners (common in phishing)
        shorteners = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
            'adf.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'shorte.st', 'soo.gd',
            's2r.co', 'bc.vc', 'adfoc.us', 'ouo.io', 'sh.st', 'ulvis.net', 'vzturl.com'
        ]
        
        for shortener in shorteners:
            if shortener in url_lower:
                return True
                
        # Check for non-standard ports (common in phishing)
        if re.search(r':(?!//)(\d{2,5})', url_lower):
            return True
            
        # Check for @ symbol in URL (trick to hide real domain)
        if '@' in url_lower:
            return True
            
        return False
