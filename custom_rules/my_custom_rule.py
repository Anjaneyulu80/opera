from ansiblelint.rules import AnsibleLintRule
from ansiblelint.utils import LintMatch

class MyCustomRule(AnsibleLintRule):
    id = "MYRULE001"
    shortdesc = "Ensure playbook has a top-level name"
    description = "Every playbook should have a 'name' field for clarity."
    severity = "MEDIUM"
    tags = ["formatting"]

    def matchplay(self, file, play):
        if "name" not in play:
            return [
                LintMatch(
                    path=file.path,            # file path
                    lineno=play.get("__line__", 0),  # optional line number
                    message="Playbook missing a top-level 'name' field"
                )
            ]
        return []
