# Super Editor

Atomic file editor for AI agents with safe writes, backups, and refactoring.

## Install

```bash
pip install super-editor
```

## Usage

```bash
# Write to a file
super-editor safe-write file.txt --content "Hello!" --write-mode write

# Read a file
super-editor safe-read file.txt --read-mode full

# Replace text
super-editor replace file.txt --pattern "old" --replacement "new"

# Line operations
super-editor line file.txt --line-number 5 --operation insert --content "New line"
```

## Features

- Atomic writes with automatic ZIP backups
- Regex and AST-based replacements
- Git integration
- 1,050 torture tests (100% pass rate)

## License

MIT
