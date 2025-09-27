class Settings: 
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Settings, cls).__new__(cls)
            cls._settings = {
                # List of known phishing domains and suspicious patterns
                'suspicious_domains': [
                    'phishing', 'hack', 'secure-', 'account-', 'login-', 'verify-', 'update-',
                    'security-', 'alert-', 'confirm-', 'billing', 'payment', 'banking', 'paypal',
                    'amazon', 'ebay', 'microsoft', 'apple', 'google', 'netflix', 'dropbox',
                    'whatsapp', 'facebook', 'linkedin', 'twitter', 'instagram', 'bank', 'chase',
                    'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 'barclays', 'santander',
                    'paypal', 'paypal-support', 'paypal-service', 'paypal-verify', 'paypal-secure',
                    'amazon-support', 'amazon-security', 'amazon-verify', 'ebay-security', 'ebay-verify',
                    'microsoft-support', 'microsoft-secure', 'microsoft-verify', 'apple-support', 'apple-verify',
                    'google-support', 'google-verify', 'netflix-support', 'netflix-verify', 'dropbox-verify',
                    'whatsapp-verify', 'facebook-verify', 'linkedin-verify', 'twitter-verify', 'instagram-verify'
                ],
                
                # Keywords that indicate urgency or pressure
                'urgent_keywords': [
                    'urgent', 'immediate', 'action required', 'account suspended', 'verify now',
                    'account locked', 'security alert', 'suspicious activity', 'login attempt',
                    'password expired', 'update now', 'confirm your account', 'verify your identity',
                    'unauthorized login', 'security breach', 'account verification', 'limited time offer',
                    'last warning', 'account termination', 'immediate action', 'take action now',
                    'your account', 'verify immediately', 'urgent action required', 'suspicious login attempt',
                    'unusual sign-in', 'verify your account', 'account restricted', 'billing problem',
                    'payment issue', 'suspension notice', 'account verification required', 'security notice',
                    'confirm your identity', 'verify your email', 'account access', 'unusual activity',
                    'verify your information', 'account security alert', 'login alert', 'password reset',
                    'account update required', 'verify your details', 'important notice', 'account notification',
                    'suspicious login', 'verify your login', 'account access required', 'security verification',
                    'verify your account now', 'urgent account notice', 'immediate verification required',
                    'account security notice', 'verify your account information', 'account security update',
                    'suspicious activity detected', 'verify your identity now', 'account access alert',
                    'important security notice', 'verify your account details', 'account security warning',
                    'suspicious login attempt', 'verify your account security', 'account access verification'
                ],
                
                # Common phishing URL patterns
                'phishing_url_patterns': [
                    r'https?://[^/]+\.(?:com|net|org|info|biz|us|uk|ca|au|in|co\.uk|co\.in)/[^/]+/verify[-_]?account',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/login[-_]?verification',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/security[-_]?alert',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/account[-_]?recovery',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/password[-_]?reset',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/billing[-_]?update',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/payment[-_]?verification',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/account[-_]?confirmation',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/identity[-_]?verification',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/secure[-_]?account',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/unlock[-_]?account',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/suspicious[-_]?activity',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/account[-_]?verification',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/login[-_]?alert',
                    r'https?://[^/]+\.(?:com|net|org)/[^/]+/security[-_]?verification'
                ],
                
                # Common suspicious email patterns
                'suspicious_email_patterns': [
                    r'[a-z0-9]+@[a-z0-9]+\.[a-z]{2,}',  # Simple email pattern
                    r'[a-z0-9]+@[a-z0-9]+\.[a-z]{2,}\.[a-z]{2,}',  # Subdomain email pattern
                    r'[a-z0-9]+@[a-z0-9]+\.[a-z0-9]+\.(?:com|net|org|biz|info|us|uk|ca|au|in)',  # Common TLDs
                    r'[a-z0-9]+@[a-z0-9]+\.[a-z0-9]+\.(?:co\.uk|co\.in|com\.au|co\.nz)',  # Country-specific TLDs
                    r'[a-z0-9]+@[a-z0-9]+\.[a-z0-9]+\.(?:gov|edu|mil|int)'  # Special TLDs
                ],
                
                # Common phishing subject patterns
                'phishing_subject_patterns': [
                    r'urgent.*account', 'verify.*account', 'suspicious.*activity',
                    'account.*suspended', 'security.*alert', 'login.*attempt',
                    'password.*expired', 'update.*now', 'confirm.*account',
                    'unauthorized.*login', 'security.*breach', 'limited.*time.*offer',
                    'last.*warning', 'account.*termination', 'immediate.*action',
                    'take.*action.*now', 'your.*account', 'verify.*immediately',
                    'urgent.*action.*required', 'suspicious.*login.*attempt',
                    'unusual.*sign-in', 'verify.*your.*account', 'account.*restricted',
                    'billing.*problem', 'payment.*issue', 'suspension.*notice',
                    'account.*verification.*required', 'security.*notice',
                    'confirm.*your.*identity', 'verify.*your.*email',
                    'account.*access', 'unusual.*activity', 'verify.*your.*information',
                    'account.*security.*alert', 'login.*alert', 'password.*reset',
                    'account.*update.*required', 'verify.*your.*details',
                    'important.*notice', 'account.*notification', 'suspicious.*login',
                    'verify.*your.*login', 'account.*access.*required',
                    'security.*verification', 'verify.*your.*account.*now',
                    'urgent.*account.*notice', 'immediate.*verification.*required',
                    'account.*security.*notice', 'verify.*your.*account.*information',
                    'account.*security.*update', 'suspicious.*activity.*detected',
                    'verify.*your.*identity.*now', 'account.*access.*alert',
                    'important.*security.*notice', 'verify.*your.*account.*details',
                    'account.*security.*warning', 'suspicious.*login.*attempt',
                    'verify.*your.*account.*security', 'account.*access.*verification'
                ]
            }
        return cls._instance

    def get_setting(self, key):
        return self.__class__._settings.get(key, [])
