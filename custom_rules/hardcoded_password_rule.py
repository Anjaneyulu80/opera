import re
from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "HardcodedPassword"
    shortdesc = "Hardcoded password or secret detected"
    description = (
        "Detects hardcoded passwords, tokens, or secrets in Ansible playbooks."
    )
    severity = "HIGH"
    tags = ["security", "password", "secret"]
    version_added = "25.9.1"
    version_changed = "25.9.1"

    def matchyaml(self, file, data):
        """
        Called once for each parsed YAML document.
        file: ansiblelint.file.Lintable
        data: dict or list with the parsed YAML
        """
        results = []

        def scan(node, path=""):
            if isinstance(node, dict):
                for key, value in node.items():
                    key_lower = str(key).lower()

                    # detect suspicious variable names
                    if any(x in key_lower for x in ["password", "secret", "token", "api_key", "key"]):
                        if (
                            isinstance(value, str)
                            and value.strip()
                            and not value.strip().startswith("$ANSIBLE_VAULT")
                        ):
                            msg = f"Hardcoded secret found: {key} = {value}"
                            results.append((path or key, msg))

                    scan(value, f"{path}.{key}" if path else key)

            elif isinstance(node, list):
                for i, item in enumerate(node):
                    scan(item, f"{path}[{i}]")

        scan(data)
        return results
