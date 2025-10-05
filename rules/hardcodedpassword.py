from ansiblelint.rules import AnsibleLintRule
from ansiblelint.utils import LINE_NUMBER_KEY

class HardcodedPasswordRule(AnsibleLintRule):
    id = 'CUSTOM001'
    shortdesc = 'Hardcoded password detected'
    description = 'Detects hardcoded passwords or secrets in YAML files.'
    severity = 'HIGH'
    tags = ['security']
    version_added = '6.0.0'

    SECRET_KEYS = ['password', 'passwd', 'secret', 'token', 'api_key']

    def matchyaml(self, file, yaml_data):
        """
        Scans parsed YAML data for hardcoded passwords or secrets.
        """
        matches = []

        def scan(data, path=''):
            if isinstance(data, dict):
                for key, value in data.items():
                    key_path = f"{path}/{key}" if path else key

                    # If key looks like a secret and value is a plain string (not a variable)
                    if any(secret in key.lower() for secret in self.SECRET_KEYS):
                        if isinstance(value, str) and '{{' not in value:
                            matches.append({
                                LINE_NUMBER_KEY: getattr(value, LINE_NUMBER_KEY, None),
                                'key_path': key_path,
                                'value': value,
                            })

                    scan(value, key_path)
            elif isinstance(data, list):
                for idx, item in enumerate(data):
                    scan(item, f"{path}[{idx}]")

        scan(yaml_data)
        return matches
