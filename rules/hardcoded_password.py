from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = 'HC100'
    shortdesc = 'Avoid hard-coded passwords'
    description = 'Passwords should not be hard-coded in playbooks or vars'
    tags = ['security', 'password']

    def matchtask(self, file, task):
        if not isinstance(task, dict):
            return False

        # Skip the standard keys
        skip_keys = ['name', 'when', 'tags', 'register', 'delegate_to', 'become']
        for key, value in task.items():
            if key in skip_keys:
                continue
            # If value is a dict (module arguments)
            if isinstance(value, dict):
                password = value.get('password')
                if password and isinstance(password, str) and not password.strip().startswith('{{'):
                    return True
        return False
