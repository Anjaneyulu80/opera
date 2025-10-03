from ansiblelint.rules import AnsibleLintRule

class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks."
    severity = "HIGH"
    tags = ["security"]
    version_changed  = "6.5.0"

    def matchtask(self, file, task):
        args = task.get("__ansible_task_arguments__", {})
        for key, value in args.items():
            if "password" in key.lower() and isinstance(value, str):
                return True
        return False
