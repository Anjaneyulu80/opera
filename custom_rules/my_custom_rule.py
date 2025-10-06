from ansiblelint.rules import AnsibleLintRule


class HardcodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Detects hardcoded passwords, tokens, or secrets in Ansible playbooks."
    severity = "HIGH"
    tags = ["security", "password"]
    version_added = "25.9.1"
    version_changed  = "25.9.1"

    def matchyaml(self, file, yaml_data):
        """
        Triggered for each parsed YAML file (playbooks, roles, etc.).
        """
        results = []

        def scan(data, path=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    key_lower = str(key).lower()
                    # Look for suspicious keys
                    if any(x in key_lower for x in ["password", "secret", "token", "api_key"]):
                        if isinstance(value, str) and value.strip():
                            msg = f"Hardcoded secret found: {key} = {value}"
                            results.append((path or key, msg))
                    scan(value, f"{path}.{key}" if path else key)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    scan(item, f"{path}[{i}]")

        scan(yaml_data)
        return results
