from ansiblelint.rules import AnsibleLintRule


class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords directly in playbooks or tasks"
    severity = "HIGH"
    tags = ["security"]
    version_changed  = "7.0.0"

    def matchtask(self, task, file):
        results = []

        # Check variables for "password"
        if "vars" in task:
            for k, v in task["vars"].items():
                if "password" in k.lower() or "password" in str(v).lower():
                    results.append(f"Hardcoded password found in var: {k}")

        # Check arguments for "password"
        if "args" in task:
            for k, v in task["args"].items():
                if "password" in k.lower() or "password" in str(v).lower():
                    results.append(f"Hardcoded password found in arg: {k}")

        return results
