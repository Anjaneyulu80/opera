import re
import math
from ansiblelint.rules import AnsibleLintRule
from ansiblelint.utils import LINE_NUMBER_KEY
import base64
import string

class HardCodedPasswordRule(AnsibleLintRule):
    id = '999'
    shortdesc = 'Avoid hardcoded secrets'
    description = 'Detect hardcoded passwords, API keys, tokens, base64, and high-entropy strings in playbooks'
    severity = 'HIGH'
    tags = ['security']
    version_added = '1.1.0'

    # Keys commonly used for secrets
    SECRET_KEYS = ['password', 'passwd', 'pass', 'secret', 'api_key', 'token', 'access_key', 'secret_key', 'client_secret']
    PLACEHOLDERS = ('<tbd>', 'changeme', 'change-me', 'dummy', 'example', 'none')

    HIGH_ENTROPY_THRESHOLD = 4.5  # Shannon entropy threshold for random strings

    BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')  # base64-like string with minimum length

    def shannon_entropy(self, s):
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        length = len(s)
        for f in freq.values():
            p = f / length
            entropy -= p * math.log2(p)
        return entropy

    def is_base64(self, s):
        """Check if string looks like base64."""
        return bool(self.BASE64_RE.match(s))

    def is_high_entropy(self, s):
        """Check if string has high entropy."""
        return self.shannon_entropy(s) >= self.HIGH_ENTROPY_THRESHOLD

    def matchyaml(self, file, yaml_data):
        matches = []

        def scan(d, path=''):
            if isinstance(d, dict):
                for k, v in d.items():
                    full_path = f"{path}/{k}" if path else k

                    # Check keys indicating secrets
                    is_secret_key = any(sk in k.lower() for sk in self.SECRET_KEYS)

                    if isinstance(v, str) and '{{' not in v and not any(ph in v.lower() for ph in self.PLACEHOLDERS):
                        flagged = False

                        # Flag if key looks like secret
                        if is_secret_key:
                            flagged = True

                        # Flag base64 string
                        elif self.is_base64(v):
                            flagged = True

                        # Flag high-entropy string
                        elif self.is_high_entropy(v):
                            flagged = True

                        if flagged:
                            preview = v if len(v) <= 60 else v[:57] + "..."
                            matches.append({
                                'file': file,
                                'line': getattr(v, LINE_NUMBER_KEY, None),
                                'key_path': full_path,
                                'value_preview': preview
                            })

                    scan(v, full_path)

            elif isinstance(d, list):
                for idx, item in enumerate(d):
                    scan(item, f"{path}[{idx}]")

        scan(yaml_data)
        return matches
