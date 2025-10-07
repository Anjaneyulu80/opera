from ansiblelint.rules import AnsibleLintRule, Match

class HardcodedPasswordRule(AnsibleLintRule):
    id = "HC100"
    shortdesc = "Avoid hard-coded passwords"
    description = "Detects hard-coded passwords in tasks, module parameters, inline content, and loops."
    severity = "HIGH"
    tags = ["security", "password"]

    def _scan_dict(self, d, task_name, file_path):
        """
        Recursively scan dictionaries for hard-coded passwords.
        Looks for keys named 'password' and inline content containing 'password'.
        Ignores Jinja template variables.
        """
        matches = []

        for key, value in d.items():
            # Recurse into nested dicts
            if isinstance(value, dict):
                matches.extend(self._scan_dict
