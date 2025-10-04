from ansiblelint.rules import AnsibleLintRule

class NoHardcodedPasswordsRule(AnsibleLintRule):
    id = '999'
    shortdesc = 'Avoid hardcoded passwords'
    description = 'Passwords should not be hardcoded in playbooks'
    severity = 'HIGH'
    tags = ['security']
    version_added = '6.0.0'  # ✅ required

    def matchyaml(self, file, yaml_data):
        matches = []

        def scan_dict(d, path=''):
            if isinstance(d, dict):
                for k, v in d.items():
                    full_path = f"{path}/{k}" if path else k
                    if 'password' in k.lower():
                        if isinstance(v, str) and '{{' not in v:
                            matches.append(full_path)
                    scan_dict(v, full_path)
            elif isinstance(d, list):
                for idx, item in enumerate(d):
                    scan_dict(item, f"{path}[{idx}]")

        scan_dict(yaml_data)
        return matches
