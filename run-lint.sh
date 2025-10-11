#!/usr/bin/env bash
set -e

echo "🔍 Step 1: Checking YAML syntax with yamllint..."
find . -type f \( -name "*.yaml" -o -name "*.yml" \) -exec yamllint {} +

echo "🚀 Step 2: Running ansible-lint with custom rules..."
ansible-lint -p

echo "✅ All checks completed successfully."
