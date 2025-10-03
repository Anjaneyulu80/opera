from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks"
    severity = "HIGH"
    tags = ["security"]
    version_changed  = "25.9.1"

    def matchtask(self, task, file=None):
        """
        task: dict of the task
        file: optional, filename
        """
        for key in ["password", "passwd"]:
            if key in task and isinstance(task[key], str):
                return True
        return False
