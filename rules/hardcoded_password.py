from ansiblelint.rules import AnsibleLintRule
from ansiblelint.utils import LINE_NUMBER_KEY

class TaskNameRule(AnsibleLintRule):
    id = 'CUSTOM001'
    shortdesc = 'All tasks should have a name'
    description = 'Every task in a playbook should have a name field.'
    severity = 'HIGH'
    tags = ['formatting']

    def matchtask(self, file, task):
        # Return True if rule is violated
        return 'name' not in task
