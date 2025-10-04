from ansiblelint.rules import AnsibleLintRule

class HardCodedPasswordRule(AnsibleLintRule):
    id = "HC100"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords directly in playbooks or tasks"
    severity = "HIGH"
    tags = ["security"]

    def matchtask(self, task, file):
        # Check vars and arguments for 'password'
        results = []
        if "vars" in task and any("password" in str(v).lower() for v in task["vars"].values()):
            results.append("Hardcoded password found in vars")

        if "args" in task and any("password" in str(v).lower() for v in task["args"].values()):
            results.append("Hardcoded password found in args")

        return results
