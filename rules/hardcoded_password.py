from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords"
    severity = "HIGH"
    tags = ["security"]

    def matchtask(self, task, file=None):
        return "password" in task
