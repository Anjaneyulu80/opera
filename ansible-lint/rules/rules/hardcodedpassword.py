from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "This rule checks for tasks that set passwords in plaintext"
    severity = "HIGH"
    tags = ["security"]

    def match(self, file, text):
        """
        file: str -> path to the YAML file being checked
        text: str -> full content of the YAML file
        """
        matches = []

        # Simple check: look for lines containing "password:"
        for i, line in enumerate(text.splitlines(), start=1):
            if 'password:' in line:
                matches.append((i, line.strip()))

        return matches
