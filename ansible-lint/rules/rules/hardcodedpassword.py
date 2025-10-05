from ansiblelint.rules import AnsibleLintRule
import math
import re

class HardcodedSecretsRule(AnsibleLintRule):
    id = 'CUSTOM001'
    shortdesc = 'Hardcoded secret detected'
    description = 'Detects hardcoded passwords, tokens, API keys, and high-entropy strings in YAML files.'
    severity = 'HIGH'
    tags = ['security']
    version_added = '8.5.0'

    # Keys that usually contain secrets
    SECRET_KEYS = ['password', 'passwd', 'secret', 'token', 'api_key', 'access_key', 'secret_key', 'client_secret']
    # Placeholder values to ignore
    PLACEHOLDERS = ('<tbd>', 'changeme', 'change-me', 'dummy', 'example', 'none')

    HIGH_ENTROPY_THRESHOLD = 4.5  # Shannon entropy threshold

    BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')  # Base64 pattern

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

        def scan(data, path=''):
            if isinstance(data, dict):
                for k, v in data.items():
                    current_path = f"{path}/{k}" if path else k
                    flagged = False

                    if isinstance(v, str) and '{{' not in v:
                        # Ignore placeholders
                        if not any(ph in v.lower() for ph in self.PLACEHOLDERS):
                            # Check if key looks like secret
                            if any(sk in k.lower() for sk in self.SECRET_KEYS):
                                flagged = True
                            # Check for base64 string
                            elif self.is_base64(v):
                                flagged = True
                            # Check high-entropy
                            elif self.is_high_entropy(v):
                                flagged = True

                    if flagged:
                        preview = v if len(v) <= 60 else v[:57] + "..."
                        matches.append({
                            'key_path': current_path,
                            'value_preview': preview
                        })

                    scan(v, current_path)

            elif isinstance(data, list):
                for idx, item in enumerate(data):
                    scan(item, f"{path}[{idx}]")

        scan(yaml_data)
        return matches
