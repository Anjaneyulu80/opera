from ansiblelint.rules import AnsibleLintRule
from ansiblelint.errors import MatchError
import re


class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks, tasks, or roles."
    severity = "HIGH"
    tags = ["security", "passwords"]
    version_added = "25.9.1"

    # simple password pattern
    _regex = re.compile(r"password\s*[:=]\s*(?:['\"].+?['\"]|\S+)", re.IGNORECASE)

    def matchlines(self, file, text: str) -> list[MatchError]:
        """Return MatchError objects so the rule ID is shown in output."""
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if self._regex.search(line):
                results.append(
                    MatchError(
                        rule=self,
                        message=self.shortdesc,
                        filename=file.path,
                        linenumber=lineno,
                    )
                )
        return results
