from ansiblelint.rules import AnsibleLintRule
class HardcodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords anywhere in tasks"
    severity = "HIGH"
    tags = ["security"]

    SENSITIVE_KEYS = ["password", "passwd", "secret", "token"]

    def matchtask(self, task, file=None):
        """
        Check for hardcoded passwords and return line numbers for reporting
        """
        matches = []
