from ansiblelint.rules import AnsibleLintRule, MatchError
import re
class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks, tasks, or roles."
    severity = "HIGH"
    tags = ["security", "passwords"]
    version_added = "25.9.1"

    _regex = re.compile(r"password\s*[:=]\s*(?:['\"].*?['\"]|\{\{.*?\}\})",
                        re.IGNORECASE)

    def matchlines(self, file, text):
        """Return list of MatchError objects so rule ID appears in output."""
        matches = []
        path = file.get("path")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if self._regex.search(line):
                matches.append(
                    MatchError(
                        rule=self,                 # tells Ansible-Lint which rule
                        filename=path,
                        linenumber=lineno,
                        message=self.shortdesc,
                    )
                )
        return matches
