from ansiblelint.rules import AnsibleLintRule
from ansiblelint.utils import LINE_NUMBER_KEY

class NoHardcodedPasswordsRule(AnsibleLintRule):
    id = '999'
    shortdesc = 'Avoid hardcoded passwords'
    description = 'Passwords should not be hardcoded in playbooks'
    severity = 'HIGH'
    tags = ['security']

    def matchplay(self, file, data):
        matches = []
        for i, line in enumerate(data.splitlines(), 1):
            if 'password:' in line and '{{' not in line:
                matches.append({LINE_NUMBER_KEY: i})
        return matches
