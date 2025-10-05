import re
from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Detects hardcoded passwords or secrets in playbooks"
    severity = "HIGH"
    tags = ["security"]

    def match(self, file, text):
        pattern = re.compile(r"(password|passwd|secret|token|api_key)\s*:")
        matches = []
        for i, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                matches.append((i, line.strip()))
        return matches
