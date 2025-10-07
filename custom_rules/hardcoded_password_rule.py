from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "Hardcoded Password"
    shortdesc = "Hardcoded password or secret detected"
    description = (
        "Detects hardcoded passwords, tokens, or secrets in Ansible playbooks."
    )
    severity = "HIGH"
    tags = ["security", "password", "secret"]
    version_added = "25.9.1"

    def matchyaml(self, file):
        results = []
        yaml_data = getattr(file, "data", None)
        if not yaml_data:
            return results

        def scan(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    key_lower = str(key).lower()
                    if any(word in key_lower for word in ["password", "secret", "token", "api_key", "key"]):
                        if isinstance(value, str) and value.strip() and not value.strip().startswith("$ANSIBLE_VAULT"):
                            msg = f"Hardcoded secret found: {key} = {value}"
                            results.append((file.path, msg))
                    scan(value)
            elif isinstance(node, list):
                for item in node:
                    scan(item)

        scan(yaml_data)
        return results
