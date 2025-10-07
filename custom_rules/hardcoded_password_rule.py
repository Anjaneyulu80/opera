from ansiblelint.rules import AnsibleLintRule, Match

class HardcodedPasswordRule(AnsibleLintRule):
    id = "HC100"
    shortdesc = "Avoid hard-coded passwords"
    description = "Passwords should not be hard-coded in playbooks."
    severity = "HIGH"
    tags = ["security", "password"]

    def matchtask(self, file, task):
        matches = []

        if not isinstance(task, dict):
            return matches

        skip_keys = ["name", "tags", "register", "delegate_to", "become", "when"]

        for key, value in task.items():
            if key in skip_keys:
                continue

            # Check nested module parameters
            if isinstance(value, dict):
                for subkey, subvalue in value.items():
                    if subkey == "password" and isinstance(subvalue, str):
                        if not subvalue.strip().startswith("{{"):
                            matches.append(
                                Match(
                                    lineno=0,
                                    filename=file["path"],
                                    rule=self,
                                    message=f"Hard-coded password found in task '{task.get('name', '')}'",
                                )
                            )

            # Check top-level password key
            if key == "password" and isinstance(value, str):
                if not value.strip().startswith("{{"):
                    matches.append(
                        Match(
                            lineno=0,
                            filename=file["path"],
                            rule=self,
                            message=f"Hard-coded password found in task '{task.get('name', '')}'",
                        )
                    )

        return matches
