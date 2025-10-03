import os
import re

PLAYBOOK_DIR = "playbooks"

PASSWORD_PATTERN = re.compile(
    r'^\s*(password|passwd|secret|token)\s*:\s*["\']?.+["\']?', re.IGNORECASE
)

def scan_file(file_path):
    results = []
    with open(file_path, "r") as f:
        for lineno, line in enumerate(f, start=1):
            if PASSWORD_PATTERN.search(line):
                results.append(f"{file_path}:{lineno}: [CUSTOM001] Hardcoded password detected")
    return results

def scan_directory(directory):
    all_results = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith((".yml", ".yaml")):
                all_results.extend(scan_file(os.path.join(root, file)))
    return all_results

if __name__ == "__main__":
    results = scan_directory(PLAYBOOK_DIR)
    for r in results:
        print(r)
