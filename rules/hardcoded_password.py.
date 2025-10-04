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

        # Recursively check the task
        def _check(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k in self.SENSITIVE_KEYS and isinstance(v, str):
                        matches.append(getattr(task, "__line__", None))
                    _check(v)
            elif isinstance(obj, list):
                for item in obj:
                    _check(item)

        _check(task)

        # Return a list of dictionaries with line numbers and messages
        return [
            {
                "linenumber": linen or 0,  # fallback if line number not found
                "message": f"[{self.id}] {self.shortdesc}"
            } for linen in matches
        ]
