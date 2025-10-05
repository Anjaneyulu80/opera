from ansiblelint.rules import AnsibleLintRule

class MyCustomRule(AnsibleLintRule):
    id = "MYRULE001"
    shortdesc = "Ensure playbook has name field"
    description = "Each playbook should have a top-level 'name' field for clarity."
    severity = "MEDIUM"
    tags = ["formatting"]

    def matchplay(self, file, play):
        if "name" not in play:
            return [("Playbook missing a name field",)]
        return []
