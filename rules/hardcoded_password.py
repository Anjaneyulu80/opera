from ansiblelint.rules import AnsibleLintRule
import re

class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks, tasks, or roles."
    severity = "HIGH"
    tags = ["security", "passwords"]
    version_changed = "25.9.1"

    # Regex to catch patterns like password: "value", password = 'value', or simple Jinja2 templates
    regex = re.compile(r'password\s*[:=]\s*(["\'].*?["\']|\{\{.*?\}\})', re.IGNORECASE)

    def matchlines(self, file, text):
        """
        Check each line for hardcoded passwords and return list of (line_number, line_text).
        AnsibleLint will format it as:
        filename:line_number: [ID] shortdesc
        """
        matches = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if self.regex.search(line):
                matches.append((lineno, line.strip()))
        return matches
