from ansiblelint.rules import AnsibleLintRule
import re

class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks, tasks, or roles."
    severity = "HIGH"
    tags = ["security", "passwords"]

    # Regex to detect password assignments
    regex = re.compile(r'password\s*[:=]\s*["\'].*["\']', re.IGNORECASE)

    def matchtask(self, task, file=None):
        """
        Recursively check tasks and their arguments for hardcoded passwords.
        Works for playbooks and roles.
        """
        # Check task arguments
        args = task.get("__ansible_task_arguments__") or task.get("args") or {}
        for key, value in args.items():
            if "password" in key.lower() and isinstance(value, str):
                return True

        # Recursively check nested tasks
        for key in ("block", "include_tasks", "import_tasks", "tasks"):
            sub_tasks = task.get(key, [])
            if isinstance(sub_tasks, list):
                for t in sub_tasks:
                    if self.matchtask(t):
                        return True

        return False

    def matchlines(self, file, text):
        """
        Check raw lines for hardcoded passwords (vars, templates, playbooks)
        """
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if self.regex.search(line):
                results.append((lineno, line.strip()))
        return results
