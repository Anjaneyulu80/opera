from ansiblelint.rules import AnsibleLintRule
import re

class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks, tasks, roles, or variables."
    severity = "HIGH"
    tags = ["security", "passwords"]
    version_changed = "6.0.0"

    # Regex to catch patterns like password: "value", password = 'value', or simple Jinja2 templates
    regex = re.compile(r'password\s*[:=]\s*(["\'].*?["\']|\{\{.*?\}\})', re.IGNORECASE)

    def matchtask(self, task, file=None):
        """
        Recursively check task arguments for hardcoded passwords.
        Works for playbooks, roles, blocks, and included/imported tasks.
        """
        # Get task arguments from either "__ansible_task_arguments__" or "args"
        args = task.get("__ansible_task_arguments__") or task.get("args") or {}
        for key, value in args.items():
            if "password" in key.lower() and isinstance(value, str):
                return True

        # Recursively check nested tasks (blocks, included/imported tasks)
        for key in ("block", "tasks", "include_tasks", "import_tasks"):
            sub_tasks = task.get(key, [])
            if isinstance(sub_tasks, list):
                for t in sub_tasks:
                    if self.matchtask(t):
                        return True

        return False

    def matchlines(self, file, text):
        """
        Check each line for hardcoded passwords.
        Useful for variables files, templates, or playbooks scanned as raw text.
        """
        matches = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if self.regex.search(line):
                matches.append((lineno, line.strip()))
        return matches
