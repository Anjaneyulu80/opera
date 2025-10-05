from ansiblelint.rules import AnsibleLintRule

class HardcodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"  # ← your rule ID
    shortdesc = "Hardcoded password detected"
    description = "This rule checks for tasks that set passwords in plaintext"
    severity = "HIGH"
    tags = ["security"]

    def match(self, file, text):
        matches = []

        # Check each line for 'password:'
        for i, line in enumerate(text.splitlines(), start=1):
            if 'password:' in line:
                # Only append line number and offending line; rule ID is used automatically
                matches.append((i, line.strip()))

        return matches
