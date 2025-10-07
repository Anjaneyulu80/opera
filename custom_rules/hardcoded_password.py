from ansiblelint.rules import AnsibleLintRule, Match

class HardcodedPasswordRule(AnsibleLintRule):
    id = "HC100"
    shortdesc = "Avoid hard-coded passwords"
    description = "Detects hard-coded passwords in module parameters, inline content, and loops."
    severity = "HIGH"
    tags = ["security", "password"]

    def _scan_value(self, value, task_name, file_path):
        matches = []

        if isinstance(value, dict):
            for k, v in value.items():
                matches.extend(self._scan_value({k: v}, task_name, file_path))
        elif isinstance(value, list):
            for item in value:
                matches.extend(self._scan_value(item, task_name, file_path))
        else:
            # Detect literal password
            if value and isinstance(value, str) and not value.strip().startswith("{{"):
                matches.append(Match(
                    lineno=0,
                    filename=file_path,
                    rule=self,
                    message=f"[{self.id}] Hard-coded password found in task '{task_name}'"
                ))

        return matches

    def _scan_task(self, task, task_name, file_path):
        matches = []
        if not isinstance(task, dict):
            return matches

        for key, value in task.items():
            if key == "name":
                continue
            if key in ["content", "line"]:
                # Check inline content for 'password' word
                if isinstance(value, str) and "password" in value.lower() and "{{" not in value:
                    matches.append(Match(
                        lineno=0,
                        filename=file_path,
                        rule=self,
                        message=f"[{self.id}] Hard-coded password found in task '{task_name}'"
                    ))
            elif key == "password":
                if isinstance(value, str) and not value.strip().startswith("{{"):
                    matches.append(Match(
                        lineno=0,
                        filename=file_path,
                        rule=self,
                        message=f"[{self.id}] Hard-coded password found in task '{task_name}'"
                    ))
            elif isinstance(value, dict):
                matches.extend(self._scan_task(value, task_name, file_path))
            elif isinstance(value, list):
                for item in value:
                    matches.extend(self._scan_task(item, task_name, file_path))
            else:
                # Catch any remaining string containing 'password'
                if isinstance(value, str) and "password" in value.lower() and "{{" not in value:
                    matches.append(Match(
                        lineno=0,
                        filename=file_path,
                        rule=self,
                        message=f"[{self.id}] Hard-coded password found in task '{task_name}'"
                    ))
        return matches

    def matchtask(self, file, task):
        task_name = task.get("name", "")
        return self._scan_task(task, task_name, file["path"])
