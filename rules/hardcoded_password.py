from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords anywhere in tasks"
    severity = "HIGH"
    tags = ["security"]

    # Keys to check for hardcoded values
    SENSITIVE_KEYS = ["password", "passwd", "secret", "token"]

    def matchtask(self, task, file=None):
        """
        Recursively check if any sensitive key has a hardcoded string
        """
        return self._check_dict(task)

    def _check_dict(self, d):
        if not isinstance(d, dict):
            return False

        for k, v in d.items():
            if k in self.SENSITIVE_KEYS and isinstance(v, str):
                return True

            # Recursive check for nested dicts
            if isinstance(v, dict) and self._check_dict(v):
                return True

            # Recursive check for lists
            if isinstance(v, list) and self._check_list(v):
                return True

        return False

    def _check_list(self, l):
        for item in l:
            if isinstance(item, dict) and self._check_dict(item):
                return True
            if isinstance(item, list) and self._check_list(item):
                return True
        return False
