from ansiblelint.rules import AnsibleLintRule
from ansiblelint.utils import LINE_NUMBER_KEY

class NoHardcodedPasswordsRule(AnsibleLintRule):
    id = 'CUSTOM001'
    shortdesc = 'Avoid hardcoded passwords'
    description = 'Passwords should not be hardcoded in playbooks'
    severity = 'HIGH'
    tags = ['security']
    version_changed = '7.0.0'

    # List of keys to detect
    SECRET_KEYS = [
        'password', 'passwd', 'pass', 'secret', 'api_key',
        'token', 'access_key', 'secret_key', 'client_secret'
    ]

    # Placeholder values to ignore
    PLACEHOLDERS = ('<tbd>', 'changeme', 'change-me', 'your_password', 'dummy', 'example', 'none')

    def matchyaml(self, file, yaml_data):
        matches = []

        def scan(d, path=''):
            """
            Recursively scan dict/list for keys containing secrets.
            """
            if isinstance(d, dict):
                for k, v in d.items():
                    full_path = f"{path}/{k}" if path else k

                    if any(sk in k.lower() for sk in self.SECRET_KEYS):
                        if isinstance(v, str):
                            lower = v.lower()
                            if '{{' not in v and not any(ph in lower for ph in self.PLACEHOLDERS):
                                # Return a dict with line number info if available
                                line_info = getattr(v, LINE_NUMBER_KEY, None)
                                # Preview truncated to 60 chars
                                preview = v if len(v) <= 60 else v[:57] + "..."
                                matches.append({
                                    LINE_NUMBER_KEY: line_info,
                                    'key_path': full_path,
                                    'value_preview': preview
                                })

                    scan(v, full_path)

            elif isinstance(d, list):
                for idx, item in enumerate(d):
                    scan(item, f"{path}[{idx}]")

        scan(yaml_data)
        return matches
