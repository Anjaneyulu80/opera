from ansiblelint.rules import AnsibleLintRule, Match

class HardcodedPasswordRule(AnsibleLintRule):
    id = "HC100"
    shortdesc = "Avoid hard-coded passwords"
    description = "Passwords should not be hard-coded in playbooks."
    severity = "HIGH"
    tags = ["security", "password"]

    def _scan_dict(self, d, task_name, file_path):
        """Recursively scan dict for hard-coded password"""
        matches = []
        for key, value in d.items():
            if isinstance(value, dict):
                matches.extend(self._scan_dict(value, task_name, file_path))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        matches.extend(self._scan_dict(item, task_name, file_path))
            else:
                if key == "password" and isinstance(value, str):
                    if not value.strip().startswith("{{"):
                        matches.append(Match(
                            lineno=0,
                            filename=file_path,
                            rule=self,
                            message=f"Hard-coded password found in task '{task_name}'"
                        ))
                # Also check inline content for passwords
                if key in ["content", "line"] and isinstance(value, str):
                    if "password" in value.lower() and not "{{" in value:
                        matches.append(Match(
                            lineno=0,
                            filename=file_path,
                            rule=self,
                            message=f"Hard-coded password found in task '{task_name}'"
                        ))
        return matches

    def matchtask(self, file, task):
        task_name = task.get("name", "")
        return self._scan_dict(task, task_name, file["path"])
