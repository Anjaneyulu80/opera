import re
from ansiblelint.rules import AnsibleLintRule

class HardcodedSecretsRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password or secret detected"
    description = (
        "Detects hardcoded passwords, tokens, or API keys in Ansible playbooks."
    )
    severity = "HIGH"
    tags = ["security"]
    version_added = "6.5.0"
    version_changed = "6.5.0"

    def matchyaml(self, file, yaml_data):
        results = []

        def scan_data(data, path=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    key_lower = str(key).lower()
                    if any(word in key_lower for word in ["password", "secret", "token", "api_key"]):
                        if isinstance(value, str) and value.strip():
                            results.append((path or key, f"{key}: {value}"))
                    scan_data(value, f"{path}.{key}" if path else key)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    scan_data(item, f"{path}[{i}]")
        scan_data(yaml_data)
        return results
