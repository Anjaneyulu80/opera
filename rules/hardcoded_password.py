from ansiblelint.rules import AnsibleLintRule

class TaskNameRule(AnsibleLintRule):
    id = 'CUSTOM001'
    shortdesc = 'All tasks should have a name'
    description = 'Every task in a playbook should have a name field.'
    
    def matchtask(self, file, task):
        return 'name' not in task
