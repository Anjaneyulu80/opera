from ansiblelint.rules import AnsibleLintRule
import re

class HardCodedPasswordRule(AnsibleLintRule):
    id = "test1"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks, tasks, or roles."
    severity = "HIGH"
    tags = ["security", "passwords"]
    version_changed = "25.9.1"

    # Regex to catch hardcoded passwords or Jinja2 templates
    regex = re.compile(r'password\s*[:=]\s*(["\'].*?["\']|\{\{.*?\}\})', re.IGNORECASE)

    def matchtask(self, task, file=None):
        """
        Recursively check task arguments for hardcoded passwords.
        Returns the line number of the task if a password is detected.
        """
        # Get task arguments safely
        args = task.get("args", {}) or {}

        for key, value in args.items():
            if "password" in key.lower() and isinstance(value, str):
                return task.get("__line__", 0)  # Return line number if found

            # Recursively check nested structures
            if isinstance(value, (dict, list)) and self._check_nested(value):
                return task.get("__line__", 0)

        # Recursively check blocks and included tasks
        for key in ("block", "include_tasks", "import_tasks", "tasks"):
            sub_tasks = task.get(key, [])
            if isinstance(sub_tasks, list):
                for t in sub_tasks:
                    line = self.matchtask(t)
                    if line:
                        return line

        return None

    def _check_nested(self, value):
        """Recursively check dicts/lists for hardcoded passwords."""
        if isinstance(value, dict):
            for k, v in value.items():
                if "password" in k.lower() and isinstance(v, str):
                    if self.regex.search(v):
                        return True
                elif isinstance(v, (dict, list)):
                    if self._check_nested(v):
                        return True
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and self.regex.search(item):
                    return True
                elif isinstance(item, (dict, list)):
                    if self._check_nested(item):
                        return True
        return False

    def matchlines(self, file, text):
        """
        Check raw lines for hardcoded passwords and return (line_number, line_text).
        This ensures ansible-lint prints: filename:line: [ID] shortdesc
        """
        matches = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if self.regex.search(line):
                matches.append((lineno, line.strip()))
        return matches
