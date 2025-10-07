from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "HARD123"
    shortdesc = "Avoid hard-coded passwords"
    description = "Detects hard-coded passwords in module parameters, inline content, and loops."
    severity = "HIGH"
    tags = ["security", "password"]

    SENSITIVE_KEYS = ["password", "passwd", "secret", "token"]

    def _scan_task(self, task):
        if not isinstance(task, dict):
            return False

        for k, v in task.items():
            if k in self.SENSITIVE_KEYS:
                if isinstance(v, str) and not v.strip().startswith("{{"):
                    return True
            elif isinstance(v, dict):
                if self._scan_task(v):
                    return True
            elif isinstance(v, list):
                for item in v:
                    if self._scan_task(item):
                        return True
            elif isinstance(v, str):
                if "password" in v.lower() and not v.strip().startswith("{{"):
                    return True
        return False

    def matchtask(self, task, file=None):
        """
        Return True if the task contains hardcoded passwords.
        """
        return self._scan_task(task)
