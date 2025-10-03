from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks"
    severity = "HIGH"
    tags = ["security"]
    version_changed  = "6.0.0"

    def matchtask(self, file, task):
        # Check if any sensitive key has a hardcoded string
        for key in ["password", "passwd"]:
            if key in task and isinstance(task[key], str):
                return True
        return False
