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

    # Regex to detect hardcoded passwords in YAML/variables
    regex = re.compile(
        r'(?i)\b(password|passwd|secret|token)\b\s*[:=]\s*["\'].*["\']'
    )

    # Common password-related task argument keys
    common_password_keys = ["password", "passwd", "secret", "token"]

    def matchtask(self, file, task):
        """
        Check task arguments for hardcoded password-like fields.
        Ignores templated variables and vault references.
        """
        for key, value in task.get("__ansible_task_arguments__", {}).items():
            key_lower = key.lower()
            if key_lower in self.common_password_keys and isinstance(value, str):
                # Ignore templated values and vault references
                if "{{" in value and "}}" in value:
                    continue
                if "vault_" in value.lower():
                    continue
                return True
        return False

    def matchlines(self, file, text):
        """
        Scan raw text lines for hardcoded passwords.
        Ignores templated variables and vault references.
        """
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            match = self.regex.search(line)
            if match:
                # Ignore lines with templated variables or vault references
                if "{{" in line or "}}" in line:
                    continue
                if "vault_" in line.lower():
                    continue
                results.append((lineno, line.strip()))
        return results
