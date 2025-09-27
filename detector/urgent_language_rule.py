import re
from typing import List, Dict, Any, Set, Tuple, Optional, Union, Callable
from .base_rule import BaseRule
from config.settings import Settings

class UrgentLanguageRule(BaseRule):
    def __init__(self):
        self.settings = Settings()
        # Pre-compile regex patterns for better performance
        self.urgency_patterns = self._compile_patterns()
        
    def _compile_patterns(self) -> List[re.Pattern]:
        """Compile regex patterns for detecting urgent language."""
        # Get patterns from settings
        patterns = self.settings.get_setting('urgent_keywords')
        
        # Add additional patterns
        additional_patterns = [
            # Time-sensitive patterns
            r'within\s+\d+\s+(?:hours?|minutes?|days?|weeks?)',
            r'only\s+\d+\s+(?:hours?|minutes?|days?|weeks?)\s+left',
            r'expir(?:y|ies|ing)\s+soon',
            r'last\s+chance',
            r'final\s+notice',
            r'act\s+now',
            r'don\'t\s+miss\s+out',
            r'limited\s+time',
            r'ending\s+soon',
            r'closing\s+soon',
            
            # Threatening language
            r'account\s+will\s+be\s+(?:suspended|closed|terminated|deactivated)',
            r'your\s+account\s+is\s+at\s+risk',
            r'immediate\s+action\s+required',
            r'failure\s+to\s+respond',
            r'your\s+access\s+will\s+be\s+revoked',
            
            # Urgent requests for personal information
            r'(?:verify|confirm|update)\s+your\s+(?:account|information|details|credentials)',
            r'(?:verify|confirm|update)\s+(?:your\s+)?(?:email|password|billing|payment)',
            r'click\s+here\s+to\s+(?:verify|confirm|update|secure)',
            
            # Financial urgency
            r'(?:unusual|suspicious)\s+activity',
            r'(?:unauthorized|fraudulent)\s+transaction',
            r'your\s+payment\s+is\s+due',
            r'payment\s+required',
            
            # General urgency
            r'important:\s*',
            r'attention\s+required',
            r'response\s+required',
            r'action\s+required',
            r'immediate\s+attention',
            r'urgent:\s*',
            r'urgent\s+notice',
            r'urgent\s+action',
            r'urgent\s+response',
            r'urgent:\s*',
            r'urgent\s+notification',
            r'urgent:\s*please\s+read',
            r'urgent:\s*account',
            r'urgent:\s*security',
            r'urgent:\s*verification',
            r'urgent:\s*update',
            r'urgent:\s*action',
            r'urgent:\s*response',
            r'urgent:\s*notice',
            r'urgent:\s*alert',
            r'urgent:\s*important',
            r'urgent:\s*attention',
            r'urgent:\s*security\s+alert',
            r'urgent:\s*account\s+alert',
            r'urgent:\s*verification\s+required',
            r'urgent:\s*update\s+required',
            r'urgent:\s*action\s+required',
            r'urgent:\s*response\s+required',
            r'urgent:\s*notice\s+of\s+suspension',
            r'urgent:\s*notice\s+of\s+closure',
            r'urgent:\s*notice\s+of\s+termination',
            r'urgent:\s*notice\s+of\s+deactivation',
            r'urgent:\s*notice\s+of\s+account\s+closure',
            r'urgent:\s*notice\s+of\s+account\s+termination',
            r'urgent:\s*notice\s+of\s+account\s+deactivation',
            r'urgent:\s*notice\s+of\s+account\s+suspension',
            r'urgent:\s*notice\s+of\s+account\s+closure',
            r'urgent:\s*notice\s+of\s+account\s+termination',
            r'urgent:\s*notice\s+of\s+account\s+deactivation',
            r'urgent:\s*notice\s+of\s+account\s+suspension'
        ]
        
        # Combine all patterns
        all_patterns = patterns + additional_patterns
        
        # Compile patterns with case-insensitive flag
        return [re.compile(pattern, re.IGNORECASE) for pattern in all_patterns]
    
    def check(self, email: Dict[str, str]) -> bool:
        """
        Check for urgent or threatening language in the email.
        Returns True if urgent language is detected.
        """
        # Combine subject and body for analysis
        subject = email.get('subject', '')
        body = email.get('body', '')
        text = f"{subject} {body}".lower()
        
        # Check for urgent language patterns
        for pattern in self.urgency_patterns:
            if isinstance(pattern, str):
                if pattern in text:
                    return True
            elif hasattr(pattern, 'search') and pattern.search(text):
                return True
        
        # Check for excessive use of exclamation marks or ALL CAPS
        if self._contains_excessive_punctuation(subject) or self._contains_excessive_caps(subject):
            return True
            
        # Check for time-sensitive language
        if self._contains_time_sensitive_language(text):
            return True
            
        # Check for threatening language
        if self._contains_threatening_language(text):
            return True
            
        return False
    
    def _contains_excessive_punctuation(self, text: str, threshold: int = 2) -> bool:
        """Check if text contains excessive punctuation (e.g., '!!!' or '???')."""
        return any(
            len(match.group()) >= threshold 
            for match in re.finditer(r'[!?]{2,}', text)
        )
    
    def _contains_excessive_caps(self, text: str, ratio: float = 0.5) -> bool:
        """Check if text contains an excessive ratio of uppercase letters."""
        if not text.strip():
            return False
            
        # Count uppercase letters and total letters
        upper_count = sum(1 for char in text if char.isupper())
        letter_count = sum(1 for char in text if char.isalpha())
        
        # Avoid division by zero
        if letter_count == 0:
            return False
            
        # Check if the ratio of uppercase letters exceeds the threshold
        return (upper_count / letter_count) > ratio
    
    def _contains_time_sensitive_language(self, text: str) -> bool:
        """Check for language that creates a false sense of urgency."""
        time_sensitive_phrases = [
            'act now', 'limited time', 'ending soon', 'only a few left',
            'offer expires', 'don\'t miss out', 'last chance', 'final notice',
            'your account will be closed', 'immediate action required',
            'your account has been compromised', 'verify your account now',
            'update your information', 'your account will be suspended',
            'your account has been locked', 'unusual login attempt',
            'suspicious activity detected', 'your account will be terminated',
            'your account has been restricted', 'your account has been limited',
            'your account has been flagged', 'your account has been blocked',
            'your account has been disabled', 'your account has been deactivated',
            'your account has been hacked', 'your account has been breached',
            'your account has been accessed', 'your account has been compromised',
            'your account has been locked for security reasons',
            'your account has been suspended for security reasons',
            'your account has been terminated for security reasons',
            'your account has been restricted for security reasons',
            'your account has been limited for security reasons',
            'your account has been flagged for security reasons',
            'your account has been blocked for security reasons',
            'your account has been disabled for security reasons',
            'your account has been deactivated for security reasons',
            'your account has been hacked for security reasons',
            'your account has been breached for security reasons',
            'your account has been accessed for security reasons',
            'your account has been compromised for security reasons'
        ]
        
        return any(phrase in text.lower() for phrase in time_sensitive_phrases)
    
    def _contains_threatening_language(self, text: str) -> bool:
        """Check for language that threatens negative consequences."""
        threatening_phrases = [
            'your account will be closed', 'your account will be suspended',
            'your account will be terminated', 'your account will be restricted',
            'your account will be limited', 'your account will be flagged',
            'your account will be blocked', 'your account will be disabled',
            'your account will be deactivated', 'your account will be hacked',
            'your account will be breached', 'your account will be accessed',
            'your account will be compromised', 'your account will be locked',
            'your account will be suspended for security reasons',
            'your account will be terminated for security reasons',
            'your account will be restricted for security reasons',
            'your account will be limited for security reasons',
            'your account will be flagged for security reasons',
            'your account will be blocked for security reasons',
            'your account will be disabled for security reasons',
            'your account will be deactivated for security reasons',
            'your account will be hacked for security reasons',
            'your account will be breached for security reasons',
            'your account will be accessed for security reasons',
            'your account will be compromised for security reasons',
            'your account will be locked for security reasons',
            'your account has been closed', 'your account has been suspended',
            'your account has been terminated', 'your account has been restricted',
            'your account has been limited', 'your account has been flagged',
            'your account has been blocked', 'your account has been disabled',
            'your account has been deactivated', 'your account has been hacked',
            'your account has been breached', 'your account has been accessed',
            'your account has been compromised', 'your account has been locked',
            'your account has been suspended for security reasons',
            'your account has been terminated for security reasons',
            'your account has been restricted for security reasons',
            'your account has been limited for security reasons',
            'your account has been flagged for security reasons',
            'your account has been blocked for security reasons',
            'your account has been disabled for security reasons',
            'your account has been deactivated for security reasons',
            'your account has been hacked for security reasons',
            'your account has been breached for security reasons',
            'your account has been accessed for security reasons',
            'your account has been compromised for security reasons',
            'your account has been locked for security reasons'
        ]
        
        return any(phrase in text.lower() for phrase in threatening_phrases)
