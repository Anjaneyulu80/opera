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
        def scan(data, path=''):
            if isinstance(data, dict):
                for k, v in data.items():
                    if 'password' in k.lower() and isinstance(v, str) and '{{' not in v:
                        matches.append({'key_path': k, 'value': v})
                    scan(v)
            elif isinstance(data, list):
                for item in data:
                    scan(item)
        scan(yaml_data)
        return matches
