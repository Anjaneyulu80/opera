from ansiblelint.rules import AnsibleLintRule
import re

class HardCodedPasswordRule(AnsibleLintRule):
    id = "CUSTOM001"
    shortdesc = "Hardcoded password detected"
    description = "Avoid hardcoding passwords in playbooks, tasks, or roles, including templated passwords."
    severity = "HIGH"
    tags = ["security", "passwords"]
    version_changed  = "25.9.1"

    # Regex to catch patterns like password: "value", password = 'value', or Jinja2 templates
    regex = re.compile(
        r'password\s*[:=]\s*(["\'].*?["\']|\{\{.*?\}\})', re.IGNORECASE
    )

    def matchtask(self, task, file=None):
        """
        Recursively check tasks and their arguments for hardcoded passwords,
        including Jinja2 templated values.
        """
        args = task.get("args", {}) or {}
        for key, value in args.items():
            if "password" in key.lower():
                if isinstance(value, str):
                    # Catch plain strings and simple Jinja2 templates
                    if re.search(r'["\'].*?["\']|\{\{.*?\}\}', value):
                        return True
                elif isinstance(value, dict) or isinstance(value, list):
                    # Recursively check if value is a dict/list
                    if self._check_nested(value):
                        return True

        # Recursively check blocks and included tasks
        for key in ("block", "include_tasks", "import_tasks", "tasks"):
            sub_tasks = task.get(key, [])
            if isinstance(sub_tasks, list):
                for t in sub_tasks:
                    if self.matchtask(t):
                        return True

        return False

    def _check_nested(self, value):
        """Recursively check dicts/lists for hardcoded passwords"""
        if isinstance(value, dict):
            for k, v in value.items():
                if "password" in k.lower() and isinstance(v, str):
                    if re.search(r'["\'].*?["\']|\{\{.*?\}\}', v):
                        return True
                elif isinstance(v, (dict, list)):
                    if self._check_nested(v):
                        return True
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    if re.search(r'["\'].*?["\']|\{\{.*?\}\}', item):
                        return True
                elif isinstance(item, (dict, list)):
                    if self._check_nested(item):
                        return True
        return False

    def matchlines(self, file, text):
        """
        Check raw lines of files for hardcoded passwords or Jinja2 templated passwords.
        Returns a list of tuples with line number and line content.
        """
        results = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if self.regex.search(line):
                results.append((lineno, line.strip()))
        return results
