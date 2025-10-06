import re
from ansiblelint.rules import AnsibleLintRule


class HardcodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = (
        "Detects hardcoded passwords, tokens, or secrets in Ansible playbooks."
    )
    severity = "HIGH"
    tags = ["security"]
    version_added = "6.5.0"
    version_changed = "6.5.0"

    def matchyaml(self, file, yaml_data):
        """
        Parse structured YAML and detect hardcoded secrets.
        """
        results = []

        def scan(data, path=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    key_lower = str(key).lower()
                    if any(x in key_lower for x in ["password", "secret", "token", "api_key"]):
                        if isinstance(value, str) and value.strip():
                            # Each match includes line info and message
                            results.append((path or key, f"{key}: {value}"))
                    scan(value, f"{path}.{key}" if path else key)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    scan(item, f"{path}[{i}]")

        scan(yaml_data)
        return results
