from ansiblelint.rules import AnsibleLintRule
import re

class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = (
        "Avoid hardcoding passwords in playbooks, variables, or tasks. "
        "Use Ansible Vault, environment variables, or external secrets managers instead."
    )
    severity = "HIGH"
    tags = ["security", "passwords", "badpractice"]

    regex = re.compile(r'password\s*[:=]\s*["\'].*["\']', re.IGNORECASE)

    def matchtask(self, file, task):
        # Check task arguments for password fields
        for key, value in task.get("__ansible_task_arguments__", {}).items():
            if "password" in key.lower() and isinstance(value, str):
                return True
        return False

    def matchlines(self, file, text):
        # Check raw text for inline hardcoded passwords
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if self.regex.search(line):
                results.append((lineno, line.strip()))
        return results
