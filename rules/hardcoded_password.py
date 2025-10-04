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
    version_changed  = "7.0.0"

    # Common sensitive keys to check
    common_password_keys = ["password", "passwd", "secret", "token"]

    # Regex to catch hardcoded secrets in YAML/variables
    regex = re.compile(
        r'(?i)\b(password|passwd|secret|token)\b\s*[:=]\s*["\'].*["\']'
    )

    def matchtask(self, file, task):
        """
        Recursively check task arguments for hardcoded password-like fields.
        Ignores templated variables and Vault references.
        """

        def check_dict(d):
            for k, v in d.items():
                key_lower = k.lower()
                if key_lower in self.common_password_keys:
                    if isinstance(v, str):
                        # Ignore templated variables or vault references
                        if "{{" in v or "}}" in v:
                            continue
                        if "!vault" in v.lower():
                            continue
                        return True
                # Recursively check nested dicts
                if isinstance(v, dict):
                    if check_dict(v):
                        return True
                # Also check lists of dicts (e.g., loops)
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
        """
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            match = self.regex.search(line)
            if match:
                # Ignore templated values and vault references
                if "{{" in line or "}}" in line:
                    continue
                if "!vault" in line.lower():
                    continue
                results.append((lineno, line.strip()))
        return results
