from ansiblelint.rules import AnsibleLintRule
import re

class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks."
    severity = "HIGH"
    tags = ["security"]

    regex = re.compile(r'password\s*[:=]\s*["\'].*["\']', re.IGNORECASE)

    def matchtask(self, file, task):
        args = task.get("__ansible_task_arguments__", {})
        for key, value in args.items():
            if "password" in key.lower() and isinstance(value, str):
                return True
        return False

    def matchlines(self, file, text):
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if self.regex.search(line):
                results.append((lineno, line.strip()))
        return results
