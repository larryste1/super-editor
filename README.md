# Super Editor

[![PyPI](https://img.shields.io/pypi/v/super-editor.svg)](https://pypi.org/project/super-editor/)
[![Downloads](https://static.pepy.tech/badge/super-editor)](https://pepy.tech/project/super-editor)
[![GitHub](https://img.shields.io/github/stars/larryste1/super-editor.svg)](https://github.com/larryste1/super-editor)

Atomic file editor with safe writes, automatic backups, and refactoring.

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

## Links

- **PyPI:** https://pypi.org/project/super-editor/
- **GitHub:** https://github.com/larryste1/super-editor

## Keywords

file editor, atomic writes, backup, automation, CLI tool, Python, Go, refactoring, safe-edit
