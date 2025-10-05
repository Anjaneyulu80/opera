from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = 'CUSTOM001'
    shortdesc = 'Hardcoded password detected'
    description = 'Detects hardcoded passwords in YAML files.'
    severity = 'HIGH'
    tags = ['security']
    version_added = '1.0.0'

    def matchyaml(self, file, yaml_data):
        matches = []
        # simple check for hardcoded passwords
        def scan(data, path=''):
            if isinstance(data, dict):
                for k, v in data.items():
                    full_path = f"{path}/{k}" if path else k
                    if 'password' in k.lower() and isinstance(v, str) and '{{' not in v:
                        matches.append({'key_path': full_path, 'value': v})
                    scan(v, full_path)
            elif isinstance(data, list):
                for idx, item in enumerate(data):
                    scan(item, f"{path}[{idx}]")
        scan(yaml_data)
        return matches
