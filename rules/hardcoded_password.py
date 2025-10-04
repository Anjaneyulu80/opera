from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords anywhere in tasks"
    severity = "HIGH"
    tags = ["security"]
    version_added = "25.9.1"

    SENSITIVE_KEYS = ["password", "passwd", "secret", "token"]

    def matchtask(self, task, file=None):
        def _check(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k in self.SENSITIVE_KEYS and isinstance(v, str):
                        return True
                    if _check(v):
                        return True
            elif isinstance(obj, list):
                for item in obj:
                    if _check(item):
                        return True
            return False

        if _check(task):
            return True
        return False
