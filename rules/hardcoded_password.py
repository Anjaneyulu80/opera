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
        Detect hardcoded passwords and return line numbers
        """
        matches = []

        def _check(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k in self.SENSITIVE_KEYS and isinstance(v, str):
                        # fallback: no line numbers, ansible-lint will mark the task
                        matches.append(0)
                    _check(v)
            elif isinstance(obj, list):
                for item in obj:
                    _check(item)

        _check(task)

        return [
            {"linenumber": linen or 0, "message": f"[{self.id}] {self.shortdesc}"}
            for linen in matches
        ]
