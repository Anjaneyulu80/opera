from ansiblelint.rules import AnsibleLintRule, Match


class HardcodedPasswordRule(AnsibleLintRule):
    id = "HC100"
    shortdesc = "Avoid hard-coded passwords"
    description = "Passwords should not be hard-coded in playbooks"
    severity = "HIGH"
    tags = ["security", "password"]

    def matchtask(self, file, task):
        """
        Return a list of Match objects if hard-coded passwords are found.
        """
        matches = []

        if not isinstance(task, dict):
            return matches

        skip_keys = ["name", "tags", "register", "delegate_to", "become", "when"]

        for key, value in task.items():
            if key in skip_keys:
                continue

            # Check module arguments for password field
            if isinstance(value, dict):
                pwd = value.get("password")
                if pwd and isinstance(pwd, str) and not pwd.strip().startswith("{{"):
                    matches.append(
                        Match(
                            lineno=0,
                            filename=file["path"],
                            rule=self,
                            message=f"Hard-coded password found in task '{task.get('name', '')}'",
                        )
                    )

            # Handle direct password field (rare)
            if key == "password" and isinstance(value, str) and not value.strip().startswith("{{"):
                matches.append(
                    Match(
                        lineno=0,
                        filename=file["path"],
                        rule=self,
                        message=f"Hard-coded password found in task '{task.get('name', '')}'",
                    )
                )

        return matches
