from ansiblelint.rules import AnsibleLintRule, MatchError
import re


class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks, tasks, or roles."
    severity = "HIGH"
    tags = ["security", "passwords"]
    version_added = "25.9.1"
    version_changed = "25.9.1"

    regex = re.compile(r"password\s*[:=]\s*(?:['\"].*?['\"]|\{\{.*?\}\})", re.IGNORECASE)

    def matchlines(self, file, text):
        """Detect hardcoded passwords and return MatchError objects with line info."""
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if self.regex.search(line):
                results.append(
                    MatchError(
                        rule=self,
                        filename=file["path"],
                        linenumber=lineno,
                        message=self.shortdesc,
                        tag="security",
                    )
                )
        return results
