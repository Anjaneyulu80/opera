from ansiblelint.rules import AnsibleLintRule
from ansiblelint.utils import LINE_OFFSET

class HardCodedPasswordRule(AnsibleLintRule):
    id = 'HC100'
    shortdesc = 'Hardcoded password detected'
    description = 'Avoid hardcoding passwords in playbooks'
    severity = 'HIGH'
    tags = ['security']

    def matchtask(self, task, file):
        # task is a dict; check for password keys
        if 'password' in task.get('vars', {}):
            return [f"Hardcoded password found in task {task.get('name')}"]
        return []
