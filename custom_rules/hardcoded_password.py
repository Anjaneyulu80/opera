from ansiblelint.rules import AnsibleLintRule
import re


class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM009"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks, tasks, or roles."
    severity = "HIGH"
    tags = ["security", "passwords"]
    version_added = "25.9.1"
    version_changed = "25.9.1"

    # Match passwords like:
    #   password: "123"
    #   password = 'abc'
    #   password: {{ something }}
    regex = re.compile(r'password\s*[:=]\s*(["\'].*?["\']|\{\{.*?\}\})', re.IGNORECASE)

    def matchlines(self, file, text):
        """
        Detect hardcoded passwords by scanning raw lines.
        Return a list of (line_number, line_content) tuples.
        """
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if self.regex.search(line):
                results.append((lineno, line.strip()))
        return results
