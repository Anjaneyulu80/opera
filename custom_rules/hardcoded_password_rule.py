from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password or secret detected"
    description = (
        "Detects hardcoded passwords, tokens, or secrets in Ansible playbooks."
    )
    severity = "HIGH"
    tags = ["security", "password", "secret"]
    version_added = "25.9.1"
    version_changed = "25.9.1"

    def matchyaml(self, file):
        results = []
        yaml_data = getattr(file, "data", None)
        if not yaml_data:
            return results

        def scan(node, path=""):
            if isinstance(node, dict):
                for key, value in node.items():
                    key_lower = str(key).lower()
                    if any(word in key_lower for word in ["password", "secret", "token", "api_key", "key"]):
                        if isinstance(value, str) and value.strip() and not value.strip().startswith("$ANSIBLE_VAULT"):
                            msg = f"Hardcoded secret found: {key} = {value}"
                            results.append((file.path, msg))
                    scan(value, f"{path}.{key}" if path else key)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    scan(item, f"{path}[{i}]")

        scan(yaml_data)
        return results
