from ansiblelint.rules import AnsibleLintRule
import re

class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = (
        "Avoid hardcoding passwords or secrets in playbooks, variables, or tasks. "
        "Use Ansible Vault, environment variables, or external secrets managers instead."
    )
    severity = "HIGH"
    tags = ["security", "passwords", "badpractice"]

    # Keys to check for sensitive information
    common_password_keys = ["password", "passwd", "secret", "token"]

    # Regex for detecting hardcoded values in YAML/variables
    regex = re.compile(r'(?i)\b(password|passwd|secret|token)\b\s*[:=]\s*["\'].*["\']')

    def matchtask(self, file, task):
        """
        Recursively check task arguments for hardcoded password-like fields.
        Ignores templated variables and vault references.
        """
        def check_dict(d):
            for k, v in d.items():
                key_lower = k.lower()
                if key_lower in self.common_password_keys and isinstance(v, str):
                    # Skip templated variables and vault references
                    if "{{" in v or "}}" in v:
                        continue
                    if "!vault" in v.lower():
                        continue
                    return True
                # Check nested dictionaries
                if isinstance(v, dict):
                    if check_dict(v):
                        return True
                # Check lists of dictionaries (loops, etc.)
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict) and check_dict(item):
                            return True
            return False

        return check_dict(task)

    def matchlines(self, file, text):
        """
        Scan raw text lines for hardcoded passwords.
        Ignores templated variables and vault references.
        Returns list of (lineno, line) tuples.
        """
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            match = self.regex.search(line)
            if match:
                # Skip templated or vault-protected lines
                if "{{" in line or "}}" in line:
                    continue
                if "!vault" in line.lower():
                    continue
                results.append((lineno, line.strip()))
        return results
