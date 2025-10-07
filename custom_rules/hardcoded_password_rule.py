import re
from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "HardcodedPasswords"
    shortdesc = "Hardcoded password or secret detected"
    description = (
        "Detects hardcoded passwords, tokens, API keys or secrets in Ansible playbooks."
    )
    severity = "HIGH"
    tags = ["security", "password", "secret"]
    version_changed = "25.9.1"
    version_added = "25.9.1"

    def matchyaml(self, file, yaml_data):
        """
        Called by ansible-lint after YAML parsing.
        `file` is a Lintable object, yaml_data is the parsed structure (dict or list).
        Return a list of (path, message) tuples.
        """
        results = []

        def scan(node, path=""):
            if isinstance(node, dict):
                for key, val in node.items():
                    key_str = str(key).lower()

                    # If the key’s name suggests it may store a secret
                    if any(word in key_str for word in ["password", "secret", "token", "api_key"]):
                        if isinstance(val, str) and val.strip():
                            msg = f"Hardcoded secret found: {key} = {val}"
                            results.append((path or key, msg))

                    # Recurse
                    scan(val, f"{path}.{key}" if path else key)

            elif isinstance(node, list):
                for idx, item in enumerate(node):
                    scan(item, f"{path}[{idx}]")

        scan(yaml_data)
        return results
