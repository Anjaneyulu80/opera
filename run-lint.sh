#!/usr/bin/env bash
set -e

echo "🔍 Step 1: Checking YAML syntax..."
find . -type f \( -name "*.yaml" -o -name "*.yml" \) -exec yamllint {} +

echo "🚀 Step 2: Running ansible-lint (with custom rule)..."
ansible-lint -p --config-file ansible-lint.yml .

echo "✅ All checks completed successfully."
