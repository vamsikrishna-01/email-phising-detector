import re
from .base_rule import BaseRule
from config.settings import Settings

class SenderAddressRule(BaseRule):
    def __init__(self):
        self.settings = Settings()
        # Pre-compile regex patterns for better performance
        self.email_pattern = re.compile(
            r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'
        )
        
    def check(self, email: dict) -> bool:
        """
        Check for suspicious sender addresses in the email.
        Returns True if the sender address is suspicious.
        """
        from_address = email.get('from', '').lower()
        
        # If no sender address is provided, it's suspicious
        if not from_address:
            return True
            
        # Extract email address if it's in "Name <email@example.com>" format
        email_match = self.email_pattern.search(from_address)
        if email_match:
            email_address = email_match.group(1).lower()
            
            # Check for suspicious domains in the email
            if self._is_suspicious_email(email_address):
                return True
                
            # Check for email spoofing (display name different from email)
            if self._is_spoofed_display_name(from_address, email_address):
                return True
                
        # Check for suspicious patterns in the entire from field
        if self._contains_suspicious_patterns(from_address):
            return True
            
        return False
    
    def _is_suspicious_email(self, email: str) -> bool:
        """Check if an email address is suspicious."""
        # Check against known suspicious domains
        suspicious_domains = self.settings.get_setting('suspicious_domains')
        for domain in suspicious_domains:
            if domain.lower() in email:
                return True
                
        # Check for email patterns that look suspicious
        email_patterns = self.settings.get_setting('suspicious_email_patterns')
        for pattern in email_patterns:
            if re.search(pattern, email, re.IGNORECASE):
                return True
                
        # Check for numeric domains (e.g., user@123.45.67.89)
        if re.search(r'@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', email):
            return True
            
        # Check for mismatched domain and TLD (e.g., paypal.com.security-update.xyz)
        if re.search(r'@[^.]+\.(?:com|net|org)\.[a-z]{2,}', email):
            return True
            
        return False
    
    def _is_spoofed_display_name(self, from_field: str, email: str) -> bool:
        """Check if the display name doesn't match the email domain."""
        # Extract display name if it exists
        name_match = re.match(r'^"?([^"]*)"?\s*<', from_field)
        if not name_match:
            return False
            
        display_name = name_match.group(1).strip()
        if not display_name:
            return False
            
        # Check if display name contains common brand names but email domain doesn't match
        common_brands = [
            'paypal', 'amazon', 'ebay', 'microsoft', 'apple', 'google', 'netflix',
            'bank', 'chase', 'wells fargo', 'bank of america', 'citibank', 'hsbc',
            'barclays', 'santander', 'whatsapp', 'facebook', 'linkedin', 'twitter',
            'instagram', 'dropbox', 'adobe', 'spotify', 'netflix', 'disney+', 'hulu'
        ]
        
        # Extract domain from email
        domain = email.split('@')[-1].lower()
        
        for brand in common_brands:
            # If display name contains a brand name but domain doesn't
            if brand in display_name.lower() and brand not in domain:
                # Allow some common email providers
                if any(provider in domain for provider in ['gmail.com', 'outlook.com', 'yahoo.com', 'icloud.com']):
                    continue
                return True
                
        return False
    
    def _contains_suspicious_patterns(self, text: str) -> bool:
        """Check for suspicious patterns in the from field."""
        text_lower = text.lower()
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'support@', 'noreply@', 'no-reply@', 'do-not-reply@', 'donotreply@',
            'security@', 'account@', 'billing@', 'payment@', 'service@', 'alert@',
            'notification@', 'verify@', 'update@', 'confirm@', 'security@', 'login@',
            'administrator@', 'admin@', 'webmaster@', 'support@', 'help@', 'info@',
            'contact@', 'mailer@', 'noreply-', 'no-reply-', 'do-not-reply-', 'donotreply-'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in text_lower:
                return True
                
        # Check for non-ASCII characters in the display name (potential homograph attack)
        if re.search(r'[^\x00-\x7F]', text):
            return True
            
        return False
