# ansible-lint-rules/hardcoded_password.py
from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = 'HC100'
    shortdesc = 'Avoid hard-coded passwords'
    description = 'Passwords should not be hard-coded in playbooks or vars'
    severity = 'HIGH'
    tags = ['security', 'password']

    def matchtask(self, file, task):
        """
        Trigger if the task contains a 'password' key with a literal value
        """
        if not isinstance(task, dict):
            return False
        password = task.get('password')
        if password and isinstance(password, str) and not password.strip().startswith('{{'):
            return True
        return False
