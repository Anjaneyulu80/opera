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
    version_changed = "1.0.0"

    common_password_keys = ["password", "passwd", "secret", "token"]
    regex = re.compile(r'(?i)\b(password|passwd|secret|token)\b\s*[:=]\s*["\'].*["\']')

    def matchtask(self, file, task):
        def check_dict(d):
            for k, v in d.items():
                key_lower = k.lower()
                if key_lower in self.common_password_keys and isinstance(v, str):
                    if "{{" in v or "}}" in v or "!vault" in v.lower():
                        continue
                    return True
                if isinstance(v, dict) and check_dict(v):
                    return True
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict) and check_dict(item):
                            return True
            return False

        return check_dict(task)

    def matchlines(self, file, text=None):
        """
        file: Lintable object
        text: optional string content (None = use file.contents)
        """
        if text is None:
            text = file.contents
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if self.regex.search(line):
                if "{{" in line or "}}" in line or "!vault" in line.lower():
                    continue
                results.append((lineno, line.strip()))
        return results
