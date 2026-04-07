import re
from .base_rule import BaseRule

class MultiAttributeRule(BaseRule):
    def __init__(self):
        # Suspicious domains commonly used in phishing
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'short.link', 't.co',
            'paypal-secure.com', 'microsoft-support.com', 'amazon-verify.com'
        ]
        
        # Keywords that indicate phishing attempts
        self.suspicious_keywords = [
            'verify', 'suspend', 'limited', 'urgent', 'immediate',
            'click here', 'confirm', 'update', 'security', 'account locked'
        ]
        
        # Legitimate domains that are often spoofed
        self.spoofed_domains = [
            'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com',
            'google.com', 'facebook.com', 'instagram.com', 'linkedin.com'
        ]
        
        # Suspicious patterns in email addresses
        self.suspicious_patterns = [
            r'\d+@',  # Numbers before @
            r'[a-z]+\d{4,}@',  # Letters followed by 4+ digits
            r'.*[.]tk$|.*[.]ml$|.*[.]ga$',  # Suspicious TLDs
            r'.*noreply.*@.*',  # Generic noreply
        ]

    def check(self, email: dict) -> bool:
        """
        Check email using 5 attributes:
        1. Sender email address analysis
        2. Subject line suspicious patterns
        3. Body content analysis
        4. Link analysis
        5. Language and urgency indicators
        """
        score = 0
        max_score = 5
        
        # Attribute 1: Sender email address analysis
        sender_score = self._analyze_sender(email.get('from', ''))
        score += sender_score
        
        # Attribute 2: Subject line analysis
        subject_score = self._analyze_subject(email.get('subject', ''))
        score += subject_score
        
        # Attribute 3: Body content analysis
        body_score = self._analyze_body(email.get('body', ''))
        score += body_score
        
        # Attribute 4: Link analysis
        link_score = self._analyze_links(email.get('body', ''))
        score += link_score
        
        # Attribute 5: Language and urgency indicators
        urgency_score = self._analyze_urgency(email.get('subject', '') + ' ' + email.get('body', ''))
        score += urgency_score
        
        # Return True if more than half the attributes indicate phishing
        return score >= 3

    def _analyze_sender(self, sender_email: str) -> int:
        """Analyze sender email address for suspicious patterns"""
        if not sender_email:
            return 1
            
        score = 0
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.match(pattern, sender_email, re.IGNORECASE):
                score += 1
                break
        
        # Check if domain is suspicious
        domain = sender_email.split('@')[-1] if '@' in sender_email else ''
        if any(susp_domain in domain for susp_domain in self.suspicious_domains):
            score += 1
        
        # Check for domain spoofing
        if any(legit_domain in domain for legit_domain in self.spoofed_domains):
            # If it contains a legitimate domain but isn't exactly that domain
            if not any(domain == legit_domain for legit_domain in self.spoofed_domains):
                score += 1
        
        return min(score, 1)

    def _analyze_subject(self, subject: str) -> int:
        """Analyze subject line for suspicious patterns"""
        if not subject:
            return 0
            
        score = 0
        
        # Check for suspicious keywords
        subject_lower = subject.lower()
        keyword_matches = sum(1 for keyword in self.suspicious_keywords if keyword in subject_lower)
        
        if keyword_matches >= 2:
            score = 1
        elif keyword_matches >= 1:
            score = 0.5
        
        # Check for ALL CAPS (common in phishing)
        if subject.isupper() and len(subject) > 5:
            score += 0.5
        
        # Check for excessive punctuation
        if subject.count('!') > 1 or subject.count('?') > 1:
            score += 0.5
        
        return min(score, 1)

    def _analyze_body(self, body: str) -> int:
        """Analyze email body content"""
        if not body:
            return 0
            
        score = 0
        body_lower = body.lower()
        
        # Check for suspicious keywords
        keyword_matches = sum(1 for keyword in self.suspicious_keywords if keyword in body_lower)
        if keyword_matches >= 3:
            score += 0.5
        elif keyword_matches >= 5:
            score += 1
        
        # Check for poor grammar indicators
        grammar_issues = 0
        if 'dear customer' in body_lower:
            grammar_issues += 1
        if body.count('!!!') > 0:
            grammar_issues += 1
        if re.search(r'\b(click|here|now|immediately)\b.*\b(link|url)\b', body_lower):
            grammar_issues += 1
        
        if grammar_issues >= 2:
            score += 0.5
        
        return min(score, 1)

    def _analyze_links(self, body: str) -> int:
        """Analyze links in the email body"""
        if not body:
            return 0
            
        score = 0
        
        # Extract URLs using regex
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, body, re.IGNORECASE)
        
        for url in urls:
            url_lower = url.lower()
            
            # Check for suspicious domains
            if any(susp_domain in url_lower for susp_domain in self.suspicious_domains):
                score += 0.5
            
            # Check for IP addresses in URLs
            if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url):
                score += 1
            
            # Check for URL shorteners
            if any(shortener in url_lower for shortener in ['bit.ly', 'tinyurl', 't.co', 'short.link']):
                score += 0.5
            
            # Check for mismatched display text vs actual URL
            if 'href=' in body.lower():
                # Look for mismatched links
                if re.search(r'href="[^"]*"[^>]*>([^<]+)<', body, re.IGNORECASE):
                    # This is a simplified check
                    pass
        
        return min(score, 1)

    def _analyze_urgency(self, text: str) -> int:
        """Analyze urgency and pressure tactics"""
        if not text:
            return 0
            
        score = 0
        text_lower = text.lower()
        
        # Urgency words
        urgency_words = [
            'urgent', 'immediately', 'now', 'today', 'hurry', 'quick',
            'limited time', 'expires', 'deadline', 'final notice'
        ]
        
        urgency_matches = sum(1 for word in urgency_words if word in text_lower)
        if urgency_matches >= 3:
            score += 0.5
        elif urgency_matches >= 5:
            score += 1
        
        # Threat words
        threat_words = [
            'suspend', 'terminate', 'close', 'delete', 'lock', 'block',
            'legal action', 'consequences', 'penalty', 'fine'
        ]
        
        threat_matches = sum(1 for word in threat_words if word in text_lower)
        if threat_matches >= 1:
            score += 0.5
        elif threat_matches >= 2:
            score += 1
        
        return min(score, 1)
