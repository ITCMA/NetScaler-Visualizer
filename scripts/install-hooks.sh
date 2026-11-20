#!/bin/sh
# Installs the repository's pre-commit hook into .git/hooks.
cd "$(git rev-parse --show-toplevel)" && cp scripts/hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit && echo "pre-commit hook installed"
