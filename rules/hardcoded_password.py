from ansiblelint.rules import AnsibleLintRule
from ansiblelint.utils import LINE_NUMBER_KEY

class HardCodedPasswordRule(AnsibleLintRule):
    id = '999'
    shortdesc = 'Avoid hardcoded passwords'
    description = 'Passwords or secrets should not be hardcoded in playbooks'
    severity = 'HIGH'
    tags = ['security']
    version_added = '1.0.0'

    SECRET_KEYS = ['password', 'passwd', 'pass', 'secret', 'api_key', 'token']
    PLACEHOLDERS = ('<tbd>', 'changeme', 'change-me', 'dummy', 'example', 'none')

    def matchyaml(self, file, yaml_data):
        """
        Scan parsed YAML for keys containing secrets.
        """
        matches = []

        def scan(d, path=''):
            if isinstance(d, dict):
                for k, v in d.items():
                    full_path = f"{path}/{k}" if path else k

                    if any(sk in k.lower() for sk in self.SECRET_KEYS):
                        if isinstance(v, str) and '{{' not in v:
                            if not any(ph in v.lower() for ph in self.PLACEHOLDERS):
                                preview = v if len(v) <= 60 else v[:57] + "..."
                                matches.append({
                                    LINE_NUMBER_KEY: getattr(v, LINE_NUMBER_KEY, None),
                                    'key_path': full_path,
                                    'value_preview': preview
                                })

                    scan(v, full_path)
            elif isinstance(d, list):
                for idx, item in enumerate(d):
                    scan(item, f"{path}[{idx}]")

        scan(yaml_data)
        return matches
