# =============================================================================
# FILENAME: super_editor_complete.py
# VERSION: 1.0
# AUTHOR: AI Assistant
# CREATED: 2026-02-03
# LAST_MODIFIED: 2026-02-03
# STATUS: EXPERIMENTAL
# 
# DESCRIPTION: Python utility file: super_editor_complete.py
# PROJECT: 
# IDEA: 
# WORKFLOW: 
# ENTRYPOINT: 
#
# USAGE: 
# FLAGS: 
# HARDENING_PROCESS: 
# PYTHON_VERSION: 3.8+
#
# DEPENDENCIES: 
# RELATED_FILES: 
# TEST_FILE: 
# CHANGE_LOG: 2026-02-03 - Initial creation
#
# LICENSE: MIT
# =============================================================================

#!/usr/bin/env python3
"""
A hardened, feature-rich file editing tool with comprehensive safety measures.
"""
import argparse
import os
import sys
import shutil
import re
from datetime import datetime
import tempfile
import difflib
import zipfile
import tarfile
import logging
import json
import subprocess
from pathlib import Path
import fnmatch
import hashlib
import threading
from functools import wraps
import time
import ast
import yaml
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional

# --- Logging Setup ---
LOG_FILE = '_project_logs/super_editor.log'
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RateLimiter:
    """Simple token bucket rate limiter"""
    def __init__(self, max_tokens: int, refill_rate: float):
        self.max_tokens = max_tokens
        self.tokens = max_tokens
        self.refill_rate = refill_rate  # tokens per second
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def acquire(self, tokens: int = 1) -> bool:
        with self.lock:
            now = time.time()
            # Refill tokens based on elapsed time
            tokens_to_add = (now - self.last_refill) * self.refill_rate
            self.tokens = min(self.max_tokens, self.tokens + tokens_to_add)
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

def retry_with_backoff(max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 60.0):
    """Decorator to retry function calls with exponential backoff"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            delay = base_delay
            
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries >= max_retries:
                        logger.error(f"Max retries exceeded after {max_retries} attempts: {e}")
                        raise
                    
                    logger.warning(f"Attempt {retries} failed: {e}. Retrying in {delay}s...")
                    time.sleep(delay)
                    delay = min(delay * 2, max_delay)  # Exponential backoff
            
            return None
        return wrapper
    return decorator

def validate_regex(pattern: str) -> tuple[bool, str]:
    """Validate a regex pattern."""
    try:
        re.compile(pattern)
        return True, None
    except re.error as e:
        return False, str(e)


# ==================== Safe Read Functions ====================

def _read_full(file_path: str, encoding: str) -> tuple[str, int]:
    """Reads the entire file content. Preserves original line endings."""
    with open(file_path, 'r', encoding=encoding, errors='strict', newline='') as f:
        read_content = f.read()
    read_bytes = len(read_content.encode(encoding))
    return read_content, read_bytes


def _read_lines(file_path: str, encoding: str, start_line: int, num_lines: int) -> tuple[str, int]:
    """Reads a specific range of lines from a file. Preserves original line endings."""
    if start_line is None or num_lines is None:
        raise ValueError("For 'lines' mode, --start_line and --num_lines are required.")
    if start_line < 0 or num_lines < 0:
        raise ValueError("start_line and num_lines must be non-negative.")

    with open(file_path, 'r', encoding=encoding, errors='strict', newline='') as f:
        lines = f.readlines()
        end_line = min(start_line + num_lines, len(lines))
        read_lines = lines[start_line:end_line]
        read_content = "".join(read_lines)
    read_bytes = len(read_content.encode(encoding))
    return read_content, read_bytes


def _read_bytes(file_path: str, encoding: str, start_byte: int, num_bytes: int) -> tuple[str, int]:
    """Reads a specific range of bytes from a file."""
    if start_byte is None or num_bytes is None:
        raise ValueError("For 'bytes' mode, --start_byte and --num_bytes are required.")
    if start_byte < 0 or num_bytes < 0:
        raise ValueError("start_byte and num_bytes must be non-negative.")

    with open(file_path, 'rb') as f:
        f.seek(start_byte)
        byte_content = f.read(num_bytes)
        read_bytes = len(byte_content)
        read_content = byte_content.decode(encoding, errors='replace')
    return read_content, read_bytes


def _read_until_pattern(file_path: str, encoding: str, until_pattern: str,
                        case_sensitive: bool, until_pattern_file: str) -> tuple[str, int]:
    """Read content until a regex pattern is found (line-by-line for memory efficiency). Preserves line endings."""
    pattern_to_use = until_pattern
    if until_pattern_file:
        if not os.path.exists(until_pattern_file):
            raise FileNotFoundError(f"Until pattern file not found: {until_pattern_file}")
        with open(until_pattern_file, 'r', encoding=encoding, newline='') as f:
            pattern_to_use = f.read()

    if not pattern_to_use:
        raise ValueError("For 'until_pattern' mode, a pattern must be provided.")

    flags = 0 if case_sensitive else re.IGNORECASE
    compiled_pattern = re.compile(pattern_to_use, flags)

    content_parts = []
    with open(file_path, 'r', encoding=encoding, errors='strict', newline='') as f:
        for line in f:
            match = compiled_pattern.search(line)
            if match:
                content_parts.append(line[:match.start()])
                break
            else:
                content_parts.append(line)

    read_content = "".join(content_parts)
    read_bytes = len(read_content.encode(encoding))
    return read_content, read_bytes


def handle_safe_read(args):
    """Handle safe read operation with multiple modes."""
    file_path = args.file_path
    encoding = args.encoding
    mode = args.read_mode
    output_file = args.output_file

    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return

    try:
        read_content = ""
        read_bytes = 0

        if mode == 'full':
            read_content, read_bytes = _read_full(file_path, encoding)
        elif mode == 'lines':
            read_content, read_bytes = _read_lines(file_path, encoding, args.start_line, args.num_lines)
        elif mode == 'bytes':
            read_content, read_bytes = _read_bytes(file_path, encoding, args.start_byte, args.num_bytes)
        elif mode == 'until_pattern':
            read_content, read_bytes = _read_until_pattern(
                file_path, encoding, args.until_pattern,
                not args.until_pattern_case_insensitive, args.until_pattern_file
            )
        else:
            logger.error(f"Invalid mode: {mode}")
            return

        # Output handling
        if output_file:
            with open(output_file, 'w', encoding=encoding) as f:
                f.write(read_content)
            logger.info(f"Read {read_bytes} bytes to {output_file}")
        elif read_bytes > 20 * 1024:
            # Too large for stdout, write to temp file
            temp_output = tempfile.NamedTemporaryFile(
                delete=False, mode='w', encoding=encoding, suffix=".tmp_super_read"
            ).name
            with open(temp_output, 'w', encoding=encoding) as f:
                f.write(read_content)
            logger.info(f"Content too large ({read_bytes} bytes), written to temp file: {temp_output}")
        else:
            # Output to stdout
            print(read_content, end='')
            logger.info(f"Read {read_bytes} bytes")

    except Exception as e:
        logger.error(f"Read error: {e}")

def get_matches_with_context(content: str, pattern: str, flags: int = 0, context_lines: int = 2):
    """Get all matches with surrounding context."""
    compiled_pattern = re.compile(pattern, flags)
    matches = []
    
    for match in compiled_pattern.finditer(content):
        start_pos = match.start()
        end_pos = match.end()
        
        # Calculate context boundaries
        start_line = content[:start_pos].count('\n')
        end_line = content[:end_pos].count('\n')
        
        # Find context lines
        lines = content.splitlines(True)
        context_start = max(0, start_line - context_lines)
        context_end = min(len(lines), end_line + context_lines + 1)
        
        match_info = {
            'match': match.group(),
            'start': start_pos,
            'end': end_pos,
            'start_line': start_line,
            'end_line': end_line,
            'context': lines[context_start:context_end],
            'context_start_line': context_start,
            'context_end_line': context_end
        }
        matches.append(match_info)
    
    return matches

def apply_conditional_replacement(content: str, pattern: str, replacement: str, 
                                condition_func=None, flags: int = 0):
    """Apply replacement with optional condition function."""
    def replacement_wrapper(match):
        if condition_func:
            if condition_func(match):
                return match.expand(replacement)
            else:
                return match.group()
        else:
            return match.expand(replacement)
    
    compiled_pattern = re.compile(pattern, flags)
    return compiled_pattern.sub(replacement_wrapper, content)

def find_files_by_pattern(directory: str, pattern: str):
    """Find files matching a glob pattern."""
    path = Path(directory)
    if pattern.startswith('*'):
        # Handle patterns like *.py
        return [f for f in path.rglob(pattern)]
    else:
        # Handle more complex patterns
        return [f for f in path.rglob('*') if fnmatch.fnmatch(f.name, pattern)]

def git_commit_changes(message: str = "Auto-commit by Super Editor"):
    """Commit changes to git if in a git repo."""
    try:
        result = subprocess.run(['git', 'add', '.'], capture_output=True, text=True, cwd=os.getcwd())
        if result.returncode == 0:
            result = subprocess.run(['git', 'commit', '-m', message], capture_output=True, text=True, cwd=os.getcwd())
            if result.returncode == 0:
                logger.info(f"Changes committed to git: {message}")
                return True
            else:
                logger.warning(f"Git commit failed: {result.stderr}")
        else:
            logger.warning(f"Git add failed: {result.stderr}")
    except FileNotFoundError:
        logger.warning("Git not found, skipping commit")
    except Exception as e:
        logger.warning(f"Git operation failed: {e}")
    
    return False

def load_pattern_library(library_path: str):
    """Load a library of predefined patterns."""
    try:
        with open(library_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading pattern library {library_path}: {e}")
        return {}

def atomic_write(file_path: str, data: str, encoding: str = 'utf-8', mode: str = 'w'):
    """
    Atomically writes data to a file, preserving permissions and line endings.
    """
    temp_file_path = None
    try:
        # Create a temporary file in the same directory to ensure atomic rename
        # Use newline='' to preserve original line endings (CRLF vs LF)
        with tempfile.NamedTemporaryFile(
            mode='w' if 'b' not in mode else 'wb',
            encoding=encoding if 'b' not in mode else None,
            dir=os.path.dirname(file_path),
            prefix=f".{os.path.basename(file_path)}.tmp-",
            delete=False,
            newline=''
        ) as temp_file:
            temp_file_path = temp_file.name
            if 'b' in mode:
                temp_file.write(data.encode(encoding) if isinstance(data, str) else data)
            else:
                temp_file.write(data)
            temp_file.flush()
            os.fsync(temp_file.fileno())

        # If the original file exists, copy its metadata (permissions, etc.)
        if os.path.exists(file_path):
            shutil.copystat(file_path, temp_file_path)

        # Atomically move the temporary file to the final destination
        shutil.move(temp_file_path, file_path)

        # Set secure file permissions (read/write for owner only)
        os.chmod(file_path, 0o600)

    except Exception as e:
        # Clean up the temporary file if it still exists after an error
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        # Re-raise the exception with more context
        raise IOError(f"Failed to atomically write to {file_path}: {e}") from e

def create_timestamped_backup(file_path: str, backup_root_dir: str = "_archive", 
                            backup_strategy: str = "archive", max_backups: int = 10):
    """
    Creates a timestamped backup of a file using specified strategy.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Original file not found for backup: {file_path}")

    absolute_backup_dir = os.path.abspath(backup_root_dir)
    os.makedirs(absolute_backup_dir, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    original_filename = os.path.basename(file_path)
    original_name, original_ext = os.path.splitext(original_filename)
    
    if backup_strategy == "simple":
        # Simple backup with timestamp
        backup_filename = f"{original_filename}.{timestamp}.bak"
        backup_path = os.path.join(absolute_backup_dir, backup_filename)
        shutil.copy2(file_path, backup_path)
    elif backup_strategy == "zip":
        # ZIP archive backup
        backup_filename = f"{original_name}_{timestamp}.zip"
        backup_path = os.path.join(absolute_backup_dir, backup_filename)
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.write(file_path, original_filename)
    elif backup_strategy == "tar":
        # TAR.GZ archive backup
        backup_filename = f"{original_name}_{timestamp}.tar.gz"
        backup_path = os.path.join(absolute_backup_dir, backup_filename)
        with tarfile.open(backup_path, "w:gz") as tar:
            tar.add(file_path, arcname=original_filename)
    else:
        # Default to simple backup
        backup_filename = f"{original_filename}.{timestamp}.bak"
        backup_path = os.path.join(absolute_backup_dir, backup_filename)
        shutil.copy2(file_path, backup_path)

    if not os.path.exists(backup_path) or (backup_strategy in ["zip", "tar"] and os.path.getsize(backup_path) == 0):
        if os.path.exists(backup_path):
            os.remove(backup_path)
        raise IOError("Backup created but appears to be empty or missing.")

    # Cleanup old backups if retention policy is active
    if max_backups > 0:
        cleanup_old_backups(absolute_backup_dir, original_name, max_backups)

    return backup_path

def cleanup_old_backups(backup_dir: str, original_name: str, max_backups: int):
    """Remove old backups to maintain retention policy."""
    backup_files = []
    for ext in ['.bak', '.zip', '.tar.gz']:
        pattern = f"{original_name}_*{ext}" if '_' in original_name else f"{original_name}*{ext}"
        backup_files.extend(Path(backup_dir).glob(pattern))
    
    # Sort by modification time (oldest first)
    backup_files.sort(key=lambda f: f.stat().st_mtime)
    
    # Remove excess backups
    while len(backup_files) > max_backups:
        old_backup = backup_files.pop(0)
        old_backup.unlink()
        logger.info(f"Removed old backup: {old_backup}")

def validate_path(path: str) -> bool:
    """Validate file path to prevent path traversal."""
    abs_path = os.path.abspath(path)
    norm_path = os.path.normpath(path)
    
    # Check for path traversal attempts
    if '..' in norm_path.split(os.sep):
        return False
    
    return True

def validate_file_type(path: str, allowed_extensions: List[str]) -> bool:
    """Validate file type based on extension."""
    _, ext = os.path.splitext(path.lower())
    return ext in allowed_extensions

def calculate_checksum(content: str, encoding: str = 'utf-8') -> str:
    """Calculate SHA-256 checksum of content."""
    if isinstance(content, str):
        content_bytes = content.encode(encoding)
    else:
        content_bytes = content
    return hashlib.sha256(content_bytes).hexdigest()

def detect_encoding(file_path: str) -> str:
    """Detect file encoding."""
    encodings = ['utf-8', 'latin-1', 'cp1252']
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                f.read()
            return encoding
        except UnicodeDecodeError:
            continue
    return 'utf-8'  # Default fallback

def convert_encoding(file_path: str, target_encoding: str):
    """Convert file to target encoding."""
    current_encoding = detect_encoding(file_path)
    if current_encoding == target_encoding:
        return  # Already in target encoding
    
    with open(file_path, 'r', encoding=current_encoding) as f:
        content = f.read()
    
    with open(file_path, 'w', encoding=target_encoding) as f:
        f.write(content)

def handle_safe_write(args):
    """
    Handles the 'safe-write' logic with unified write modes and all safety features.
    """
    file_path = args.file_path
    content = args.content
    mode = args.write_mode
    dry_run = args.dry_run
    backup_dir = args.backup_dir
    backup_strategy = args.backup_strategy
    max_backups = args.max_backups
    encoding = args.encoding
    allowed_extensions = args.allowed_extensions.split(',') if args.allowed_extensions else ['.txt', '.py', '.json', '.yaml', '.yml', '.xml', '.html', '.css', '.js']
    max_file_size = args.max_file_size
    
    logger.info(f"Executing 'safe-write' command for file: {file_path}")
    logger.info(f"  Mode: {mode}")
    logger.info(f"  Content length: {len(content) if content else 0} chars")
    logger.info(f"  Dry Run: {dry_run}")
    logger.info(f"  Backup Directory: {backup_dir}")
    logger.info(f"  Backup Strategy: {backup_strategy}")

    # Validate path
    if not validate_path(file_path):
        logger.error(f"Invalid file path: '{file_path}'. Path traversal detected.")
        sys.exit(1)
    
    # Validate file type if specified
    if not validate_file_type(file_path, allowed_extensions):
        logger.error(f"File type not allowed: '{file_path}'. Allowed: {allowed_extensions}")
        sys.exit(1)
    
    # Validate content size
    if max_file_size > 0 and len(content or "") > max_file_size:
        logger.error(f"Content exceeds maximum size limit of {max_file_size} characters")
        sys.exit(1)
    
    # Check if file exists and get original content for diff
    # Use newline='' to preserve original line endings (CRLF vs LF)
    original_content = ""
    file_exists = os.path.exists(file_path)
    if file_exists and mode != 'write':
        with open(file_path, 'r', encoding=encoding, newline='') as f:
            original_content = f.read()
    
    # Prepare content based on mode
    if mode == 'write':
        final_content = content
    elif mode == 'append':
        final_content = original_content + content if file_exists else content
    elif mode == 'prepend':
        final_content = content + original_content if file_exists else content
    else:
        logger.error(f"Invalid write mode: {mode}")
        sys.exit(1)
    
    # Calculate checksum
    checksum = calculate_checksum(final_content, encoding)
    logger.info(f"Content checksum: {checksum}")

    if dry_run:
        print(f"\n--- Dry Run: Proposed Changes ---")
        if file_exists:
            diff = difflib.unified_diff(
                original_content.splitlines(keepends=True),
                final_content.splitlines(keepends=True),
                fromfile=f"a/{os.path.basename(file_path)}",
                tofile=f"b/{os.path.basename(file_path)}",
                lineterm=''
            )
            for line in diff:
                if line.startswith('+'):
                    print(f"\033[32m{line}\033[0m")  # Green for added lines
                elif line.startswith('-'):
                    print(f"\033[31m{line}\033[0m")  # Red for removed lines
                elif line.startswith('@'):
                    print(f"\033[36m{line}\033[0m")  # Cyan for header
                else:
                    print(line)
        else:
            print(f"New file would be created with {len(final_content)} characters")
        print("------------------------------------\n")
        logger.info("Dry run completed. No changes made.")
        return

    # Create backup if file exists
    backup_path = None
    if file_exists:
        try:
            backup_path = create_timestamped_backup(file_path, backup_dir, backup_strategy, max_backups)
            logger.info(f"Successfully created backup at: {backup_path}")
        except (FileNotFoundError, IOError) as e:
            logger.error(f"Error: Backup failed. Aborting operation. Details: {e}")
            sys.exit(1)

    # Interactive confirmation if requested
    if args.interactive:
        print(f"\n--- Proposed Changes ---")
        if file_exists:
            diff = difflib.unified_diff(
                original_content.splitlines(keepends=True),
                final_content.splitlines(keepends=True),
                fromfile=f"a/{os.path.basename(file_path)}",
                tofile=f"b/{os.path.basename(file_path)}",
                lineterm=''
            )
            for line in diff:
                if line.startswith('+'):
                    print(f"\033[32m{line}\033[0m")  # Green for added lines
                elif line.startswith('-'):
                    print(f"\033[31m{line}\033[0m")  # Red for removed lines
                elif line.startswith('@'):
                    print(f"\033[36m{line}\033[0m")  # Cyan for header
                else:
                    print(line)
        else:
            print(f"New file with {len(final_content)} characters")
        print("------------------------\n")
        
        response = input("Do you want to apply these changes? (y/N): ").strip().lower()
        if response != 'y':
            logger.info("Operation aborted by user.")
            return

    # Write the content atomically
    try:
        atomic_write(file_path, final_content, encoding=encoding, mode='w')
        logger.info(f"Successfully wrote {len(final_content)} characters to {file_path} using atomic write.")
        
        # Commit to git if requested
        if args.git_commit:
            git_commit_changes(f"Super Editor: Write content to {file_path}")
            
    except IOError as e:
        logger.error(f"Error: Failed to write changes to file. Details: {e}")
        sys.exit(1)

def handle_replace(args):
    """
    Handles the 'replace' logic, including mandatory backup, find-and-replace, and atomic write.
    """
    file_path = args.file_path
    pattern = args.pattern
    replacement = args.replacement
    dry_run = args.dry_run
    backup_dir = args.backup_dir
    backup_strategy = args.backup_strategy
    max_backups = args.max_backups
    regex_flags = 0
    
    # Handle regex flags
    if args.multiline:
        regex_flags |= re.MULTILINE
    if args.dotall:
        regex_flags |= re.DOTALL
    if args.ignore_case:
        regex_flags |= re.IGNORECASE
    if args.verbose:
        regex_flags |= re.VERBOSE

    logger.info(f"Executing 'replace' command for file: {file_path}")
    logger.info(f"  Pattern: {pattern}")
    logger.info(f"  Replacement: {replacement}")
    logger.info(f"  Regex flags: {regex_flags}")
    logger.info(f"  Dry Run: {dry_run}")
    logger.info(f"  Backup Directory: {backup_dir}")
    logger.info(f"  Backup Strategy: {backup_strategy}")

    # Validate regex if not literal
    if not args.literal:
        is_valid, error_msg = validate_regex(pattern)
        if not is_valid:
            logger.error(f"Invalid regex pattern: {error_msg}")
            sys.exit(1)

    if not os.path.exists(file_path):
        logger.error(f"Error: File not found: {file_path}")
        sys.exit(1)
    else:
        # Main try block for file reading and regex replacement
        # Use newline='' to preserve original line endings
        try:
            with open(file_path, 'r', encoding='utf-8', newline='') as f:
                original_content = f.read()

            # Get matches with context if requested
            if args.show_context:
                matches = get_matches_with_context(original_content, pattern, regex_flags, args.context_lines)
                logger.info(f"Found {len(matches)} matches:")
                for i, match in enumerate(matches):
                    logger.info(f"  Match {i+1}: Line {match['start_line']+1}, '{match['match']}'")

            # Apply replacement
            if args.conditional:
                # For conditional replacement, we'd need a more complex implementation
                # This is a simplified version - in practice, you'd define conditions differently
                new_content = apply_conditional_replacement(original_content, pattern, replacement, flags=regex_flags)
            else:
                # Determine if we should treat the pattern as a literal or regex
                # By default, we treat it as literal unless --regex is explicitly specified
                search_pattern = pattern
                if not args.regex:  # Default behavior is literal unless --regex is specified
                    search_pattern = re.escape(pattern)

                new_content, replacements_made = re.subn(search_pattern, replacement, original_content, flags=regex_flags)

            if original_content == new_content:
                # Provide a more informative error message
                if args.regex:
                    logger.error(f"Error: Regex pattern '{pattern}' not found in file {file_path}")
                    logger.info("Note: By default, patterns are treated as literal text. Use --literal to match exact string.")
                else:
                    logger.error(f"Error: Literal pattern '{pattern}' not found in file {file_path}")
                    logger.info("Note: Use --regex flag if you want to treat the pattern as a regular expression.")
                sys.exit(1)

            # Generate and display the diff (remains print for direct user feedback)
            print(f"\n--- Proposed Changes ({replacements_made} replacement(s) found) ---")
            diff = difflib.unified_diff(
                original_content.splitlines(keepends=True),
                new_content.splitlines(keepends=True),
                fromfile=f"a/{os.path.basename(file_path)}",
                tofile=f"b/{os.path.basename(file_path)}",
                lineterm='' # Prevent extra newlines if the input already has them
            )
            # Adding color to the diff output for better readability
            for line in diff:
                if line.startswith('+'):
                    print(f"\033[32m{line}\033[0m")  # Green for added lines
                elif line.startswith('-'):
                    print(f"\033[31m{line}\033[0m")  # Red for removed lines
                elif line.startswith('@'):
                    print(f"\033[36m{line}\033[0m")  # Cyan for header
                else:
                    print(line)
            print("--------------------------------------------------\n")

            # --- Task 4: Dry-Run Mode ---
            if dry_run:
                logger.info("Dry run requested. No changes written to file. No backup is created if --dry-run is used.")
                return # Exit cleanly without modifying the file

            # --- Task 3: Mandatory Backup (Integration) ---
            try:
                backup_path = create_timestamped_backup(file_path, backup_dir, backup_strategy, max_backups)
                logger.info(f"Successfully created backup at: {backup_path}")
            except (FileNotFoundError, IOError) as e:
                logger.error(f"Error: Backup failed. Aborting operation. Details: {e}")
                sys.exit(1)

            # --- Task 5: Interactive Confirmation ---
            if not args.non_interactive:
                response = input("Do you want to apply these changes? (y/N): ").strip().lower()
                if response != 'y':
                    logger.info("Operation aborted by user.")
                    return

            # Try block for atomic write
            try:
                atomic_write(file_path, new_content, encoding='utf-8')
                logger.info(f"Successfully applied {replacements_made} replacement(s) to {file_path} using atomic write.")
                
                # Commit to git if requested
                if args.git_commit:
                    git_commit_changes(f"Super Editor: Replace '{pattern}' with '{replacement}' in {file_path}")
                    
            except IOError as e:
                logger.error(f"Error: Failed to write changes to file. Details: {e}")
                sys.exit(1) # Exit if atomic write fails

        except IOError as e:
            logger.error(f"Error reading file {file_path}: {e}")
            sys.exit(1)
        except re.error as e:
            logger.error(f"Error: Invalid regex pattern: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
            sys.exit(1)

def handle_line_operations(args):
    """Handle line-level operations (insert, delete, replace by line number)."""
    file_path = args.file_path
    operation = args.line_operation
    line_number = args.line_number
    content = args.content
    backup_dir = args.backup_dir
    backup_strategy = args.backup_strategy
    max_backups = args.max_backups

    if not os.path.exists(file_path):
        logger.error(f"Error: File not found: {file_path}")
        sys.exit(1)

    # Use newline='' to preserve original line endings
    try:
        with open(file_path, 'r', encoding='utf-8', newline='') as f:
            lines = f.readlines()

        if operation == 'delete':
            if 1 <= line_number <= len(lines):
                deleted_line = lines.pop(line_number - 1)
                logger.info(f"Deleted line {line_number}: {deleted_line.strip()}")
            else:
                logger.error(f"Error: Line number {line_number} is out of range (1-{len(lines)})")
                sys.exit(1)
        
        elif operation == 'insert':
            if 1 <= line_number <= len(lines) + 1:
                lines.insert(line_number - 1, content + '\n')
                logger.info(f"Inserted content at line {line_number}")
            else:
                logger.error(f"Error: Line number {line_number} is out of range (1-{len(lines) + 1})")
                sys.exit(1)
        
        elif operation == 'replace':
            if 1 <= line_number <= len(lines):
                old_content = lines[line_number - 1]
                lines[line_number - 1] = content + '\n'
                logger.info(f"Replaced line {line_number}: {old_content.strip()} -> {content}")
            else:
                logger.error(f"Error: Line number {line_number} is out of range (1-{len(lines)})")
                sys.exit(1)
        
        # Create backup before writing
        backup_path = create_timestamped_backup(file_path, backup_dir, backup_strategy, max_backups)
        logger.info(f"Successfully created backup at: {backup_path}")
        
        # Write the modified content
        atomic_write(file_path, ''.join(lines), encoding='utf-8')
        logger.info(f"Successfully performed {operation} operation on line {line_number}")
        
    except IOError as e:
        logger.error(f"Error processing file {file_path}: {e}")
        sys.exit(1)

def handle_structured_data(args):
    """Handle structured data operations (JSON, YAML, XML)."""
    file_path = args.file_path
    operation = args.struct_operation
    key_path = args.key
    value = args.value
    backup_dir = args.backup_dir
    backup_strategy = args.backup_strategy
    max_backups = args.max_backups
    
    if not os.path.exists(file_path):
        logger.error(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    # Determine file type based on extension
    _, ext = os.path.splitext(file_path.lower())
    
    try:
        if ext == '.json':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if operation == 'get':
                # Navigate to the key
                keys = key_path.split('.')
                current = data
                for k in keys:
                    current = current[k]
                print(json.dumps(current, indent=2))
                
            elif operation == 'set':
                # Navigate to the parent of the target key
                keys = key_path.split('.')
                current = data
                for k in keys[:-1]:
                    current = current[k]
                
                # Set the value
                current[keys[-1]] = json.loads(value) if value.startswith(('{', '[')) else value
                logger.info(f"Set {key_path} to {value}")
                
            elif operation == 'delete':
                # Navigate to the parent of the target key
                keys = key_path.split('.')
                current = data
                for k in keys[:-1]:
                    current = current[k]
                
                # Delete the key
                del current[keys[-1]]
                logger.info(f"Deleted {key_path}")
            
            # Write back to file
            with open(file_path, 'w', encoding='utf-8', newline='') as f:
                json.dump(data, f, indent=2)

        elif ext in ['.yaml', '.yml']:
            with open(file_path, 'r', encoding='utf-8', newline='') as f:
                data = yaml.safe_load(f)
            
            if operation == 'get':
                # Navigate to the key
                keys = key_path.split('.')
                current = data
                for k in keys:
                    current = current[k]
                print(yaml.dump(current, default_flow_style=False))
                
            elif operation == 'set':
                # Navigate to the parent of the target key
                keys = key_path.split('.')
                current = data
                for k in keys[:-1]:
                    current = current[k]
                
                # Set the value
                current[keys[-1]] = value
                logger.info(f"Set {key_path} to {value}")
                
            elif operation == 'delete':
                # Navigate to the parent of the target key
                keys = key_path.split('.')
                current = data
                for k in keys[:-1]:
                    current = current[k]
                
                # Delete the key
                del current[keys[-1]]
                logger.info(f"Deleted {key_path}")
            
            # Write back to file
            with open(file_path, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False)
        
        elif ext == '.xml':
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            if operation == 'get':
                elements = root.findall(key_path)
                for elem in elements:
                    print(ET.tostring(elem, encoding='unicode'))
                    
            elif operation == 'set':
                elements = root.findall(key_path)
                for elem in elements:
                    elem.text = value
                logger.info(f"Set {key_path} to {value}")
                
            elif operation == 'delete':
                # Find parent elements
                parent_map = {c: p for p in tree.iter() for c in p}
                elements = root.findall(key_path)
                for elem in elements:
                    parent = parent_map[elem]
                    parent.remove(elem)
                logger.info(f"Deleted {key_path}")
            
            # Write back to file
            tree.write(file_path, encoding='unicode', xml_declaration=True)
        
        else:
            logger.error(f"Unsupported structured data format: {ext}")
            sys.exit(1)
        
        # Create backup after successful operation
        backup_path = create_timestamped_backup(file_path, backup_dir, backup_strategy, max_backups)
        logger.info(f"Successfully created backup at: {backup_path}")
        
    except Exception as e:
        logger.error(f"Error processing structured data file {file_path}: {e}")
        sys.exit(1)

def handle_ast_refactor(args):
    """Handle AST-based refactoring for Python files."""
    file_path = args.file_path
    operation = args.refactor_operation
    target = args.target
    backup_dir = args.backup_dir
    backup_strategy = args.backup_strategy
    max_backups = args.max_backups
    
    if not os.path.exists(file_path):
        logger.error(f"Error: File not found: {file_path}")
        sys.exit(1)

    if not file_path.endswith('.py'):
        logger.error(f"Error: AST refactoring only works with Python files: {file_path}")
        sys.exit(1)

    # Use newline='' to preserve original line endings
    try:
        with open(file_path, 'r', encoding='utf-8', newline='') as f:
            source = f.read()

        tree = ast.parse(source)
        
        if operation == 'rename':
            # This is a simplified implementation - a full implementation would be more complex
            # For now, we'll just do a simple find-and-replace for the identifier
            new_source = re.sub(r'\b' + re.escape(target) + r'\b', args.new_name, source)
            logger.info(f"Renamed '{target}' to '{args.new_name}'")
        
        elif operation == 'remove':
            # Remove all occurrences of a function/class definition
            new_tree = RemoveFunctionVisitor(target).visit(tree)
            new_source = ast.unparse(new_tree)  # Note: ast.unparse is available in Python 3.9+
            logger.info(f"Removed '{target}'")
        
        else:
            logger.error(f"Unsupported refactoring operation: {operation}")
            sys.exit(1)
        
        # Create backup before writing
        backup_path = create_timestamped_backup(file_path, backup_dir, backup_strategy, max_backups)
        logger.info(f"Successfully created backup at: {backup_path}")
        
        # Write the refactored code
        atomic_write(file_path, new_source, encoding='utf-8')
        logger.info(f"Successfully performed {operation} refactoring on {file_path}")
        
    except SyntaxError as e:
        logger.error(f"Syntax error in Python file {file_path}: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error during AST refactoring of {file_path}: {e}")
        sys.exit(1)

class RemoveFunctionVisitor(ast.NodeTransformer):
    """AST visitor to remove function definitions."""
    def __init__(self, func_name):
        self.func_name = func_name
    
    def visit_FunctionDef(self, node):
        if node.name == self.func_name:
            return None  # Remove this node
        return self.generic_visit(node)

def handle_comment_operations(args):
    """Handle code-aware comment operations."""
    file_path = args.file_path
    operation = args.comment_operation
    language = args.language or os.path.splitext(file_path)[1][1:]  # Get extension without dot
    backup_dir = args.backup_dir
    backup_strategy = args.backup_strategy
    max_backups = args.max_backups
    
    # Define comment patterns for different languages
    comment_patterns = {
        'py': {'single': '#', 'multi_start': '"""', 'multi_end': '"""'},
        'js': {'single': '//', 'multi_start': '/*', 'multi_end': '*/'},
        'java': {'single': '//', 'multi_start': '/*', 'multi_end': '*/'},
        'cpp': {'single': '//', 'multi_start': '/*', 'multi_end': '*/'},
        'c': {'single': '//', 'multi_start': '/*', 'multi_end': '*/'},
        'html': {'single': '', 'multi_start': '<!--', 'multi_end': '-->'},
        'css': {'single': '', 'multi_start': '/*', 'multi_end': '*/'},
    }
    
    if language not in comment_patterns:
        logger.error(f"Unsupported language for comment operations: {language}")
        sys.exit(1)
    
    if not os.path.exists(file_path):
        logger.error(f"Error: File not found: {file_path}")
        sys.exit(1)

    # Use newline='' to preserve original line endings
    try:
        with open(file_path, 'r', encoding='utf-8', newline='') as f:
            lines = f.readlines()

        if operation == 'toggle_single':
            line_num = args.line_number - 1
            if 0 <= line_num < len(lines):
                pattern = comment_patterns[language]['single']
                stripped = lines[line_num].lstrip()
                if stripped.startswith(pattern):
                    # Uncomment
                    idx = lines[line_num].index(stripped)
                    lines[line_num] = lines[line_num][:idx] + stripped[len(pattern):].lstrip()
                    logger.info(f"Uncommented line {args.line_number}")
                else:
                    # Comment
                    leading_spaces = len(lines[line_num]) - len(lines[line_num].lstrip())
                    lines[line_num] = ' ' * leading_spaces + pattern + ' ' + stripped
                    logger.info(f"Commented line {args.line_number}")
            else:
                logger.error(f"Error: Line number {args.line_number} is out of range")
                sys.exit(1)
        
        # Create backup before writing
        backup_path = create_timestamped_backup(file_path, backup_dir, backup_strategy, max_backups)
        logger.info(f"Successfully created backup at: {backup_path}")
        
        # Write the modified content
        atomic_write(file_path, ''.join(lines), encoding='utf-8')
        logger.info(f"Successfully performed {operation} comment operation on line {args.line_number}")
        
    except IOError as e:
        logger.error(f"Error processing file {file_path}: {e}")
        sys.exit(1)

def handle_batch_replace(args):
    """Handle batch replacement across multiple files."""
    pattern = args.pattern
    replacement = args.replacement
    backup_dir = args.backup_dir
    backup_strategy = args.backup_strategy
    max_backups = args.max_backups
    
    # Handle regex flags
    regex_flags = 0
    if args.multiline:
        regex_flags |= re.MULTILINE
    if args.dotall:
        regex_flags |= re.DOTALL
    if args.ignore_case:
        regex_flags |= re.IGNORECASE

    # Validate regex if not literal
    if not args.literal:
        is_valid, error_msg = validate_regex(pattern)
        if not is_valid:
            logger.error(f"Invalid regex pattern: {error_msg}")
            sys.exit(1)

    # Find files to process
    files_to_process = []
    if args.files:
        files_to_process = [Path(f) for f in args.files]
    elif args.glob_pattern:
        files_to_process = find_files_by_pattern(args.directory or '.', args.glob_pattern)
    
    # Apply replacements to each file
    for file_path in files_to_process:
        if file_path.is_file():
            logger.info(f"Processing file: {file_path}")
            
            # Create backup
            try:
                backup_path = create_timestamped_backup(str(file_path), backup_dir, backup_strategy, max_backups)
                logger.info(f"Created backup: {backup_path}")
            except Exception as e:
                logger.error(f"Failed to create backup for {file_path}: {e}")
                continue
            
            # Read and modify content
            # Use newline='' to preserve original line endings
            try:
                with open(file_path, 'r', encoding='utf-8', newline='') as f:
                    original_content = f.read()

                new_content, replacements_made = re.subn(pattern, replacement, original_content, flags=regex_flags)
                
                if original_content != new_content:
                    atomic_write(str(file_path), new_content, encoding='utf-8')
                    logger.info(f"Applied {replacements_made} replacement(s) to {file_path}")
                else:
                    logger.info(f"No changes needed for {file_path}")
                    
            except Exception as e:
                logger.error(f"Error processing {file_path}: {e}")

def handle_undo(args):
    """Handle undo operation using backups."""
    backup_dir = args.backup_dir
    file_path = args.file_path
    
    # Look for the most recent backup
    backup_files = []
    backup_path = Path(backup_dir)
    if backup_path.exists():
        for backup_file in backup_path.glob(f"{Path(file_path).name}_*.zip"):
            backup_files.append((backup_file, backup_file.stat().st_mtime))
        
        if backup_files:
            # Sort by modification time (most recent first)
            backup_files.sort(key=lambda x: x[1], reverse=True)
            latest_backup = backup_files[0][0]
            
            logger.info(f"Restoring from backup: {latest_backup}")
            
            # Extract the backup
            with zipfile.ZipFile(latest_backup, 'r') as zf:
                zf.extractall(path=Path(file_path).parent)
                
            logger.info(f"Restored {file_path} from {latest_backup}")
        else:
            logger.error(f"No backups found for {file_path} in {backup_dir}")
    else:
        logger.error(f"Backup directory {backup_dir} does not exist")

def main():
    parser = argparse.ArgumentParser(
        prog='super_editor',
        description='Super Editor - A robust, universal file editing tool.'
    )
    subparsers = parser.add_subparsers(
        dest='command',
        required=True,
        help='The editing command to execute.'
    )

    # Safe Write command (unified write/append/prepend)
    write_parser = subparsers.add_parser(
        'safe-write',
        help='Safely write content to a file with multiple modes and safety features.',
        description='Write, append, or prepend content to a file with comprehensive safety measures.'
    )
    write_parser.add_argument(
        'file_path',
        metavar='FILE',
        type=os.path.abspath,
        help='The path to the file to be edited.'
    )
    write_parser.add_argument(
        '--content',
        required=True,
        help='The content to write to the file.'
    )
    write_parser.add_argument(
        '--write-mode',
        choices=['write', 'append', 'prepend'],
        default='write',
        help='The write mode: write (overwrite), append, or prepend (default: write).'
    )
    write_parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Simulate the operation without modifying the file.'
    )
    write_parser.add_argument(
        '--backup-dir',
        default='_archive',
        help='The directory to store backups in (default: _archive).'
    )
    write_parser.add_argument(
        '--backup-strategy',
        choices=['simple', 'zip', 'tar'],
        default='zip',
        help='The backup strategy to use (default: zip).'
    )
    write_parser.add_argument(
        '--max-backups',
        type=int,
        default=10,
        help='Maximum number of old backups to keep (default: 10, 0 for unlimited).'
    )
    write_parser.add_argument(
        '--encoding',
        default='utf-8',
        help='Character encoding for the file (default: utf-8).'
    )
    write_parser.add_argument(
        '--allowed-extensions',
        default='.txt,.py,.json,.yaml,.yml,.xml,.html,.css,.js',
        help='Comma-separated list of allowed file extensions (default: common text-based formats).'
    )
    write_parser.add_argument(
        '--max-file-size',
        type=int,
        default=10485760,  # 10MB
        help='Maximum file size in bytes (default: 10MB, 0 for unlimited).'
    )
    write_parser.add_argument(
        '--interactive',
        action='store_true',
        help='Show diff and ask for confirmation before writing.'
    )
    write_parser.add_argument(
        '--git-commit',
        action='store_true',
        help='Commit changes to git after successful write.'
    )
    write_parser.set_defaults(func=handle_safe_write)

    # Replace command
    replace_parser = subparsers.add_parser(
        'replace',
        help='Find and replace text in a file.',
        description='Performs a find-and-replace operation with regex support.'
    )
    replace_parser.add_argument(
        'file_path',
        metavar='FILE',
        type=os.path.abspath,
        help='The path to the file to be edited.'
    )
    replace_parser.add_argument(
        '--pattern',
        required=True,
        help='The search pattern (treated as literal text by default, use --regex for regular expressions).'
    )
    replace_parser.add_argument(
        '--replacement',
        required=True,
        help='The string to replace the pattern with.'
    )
    
    # Regex flags
    replace_parser.add_argument(
        '--multiline', 
        action='store_true',
        help='Enable multiline matching (^ and $ match start/end of lines).'
    )
    replace_parser.add_argument(
        '--dotall',
        action='store_true',
        help='Make . match newline characters too.'
    )
    replace_parser.add_argument(
        '--ignore-case',
        action='store_true',
        help='Case-insensitive matching.'
    )
    replace_parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose pattern compilation (whitespace and comments).'
    )
    
    # Context options
    replace_parser.add_argument(
        '--show-context',
        action='store_true',
        help='Show context around matches.'
    )
    replace_parser.add_argument(
        '--context-lines',
        type=int,
        default=2,
        help='Number of context lines to show around matches (default: 2).'
    )
    
    # Conditional replacement
    replace_parser.add_argument(
        '--conditional',
        action='store_true',
        help='Apply conditional replacement logic.'
    )
    
    # Git integration
    replace_parser.add_argument(
        '--git-commit',
        action='store_true',
        help='Commit changes to git after successful replacement.'
    )

    replace_parser.add_argument(
        '--literal',
        action='store_true',
        help='Treat the search pattern as a literal string, not a regex (this is the default behavior).'
    )
    replace_parser.add_argument(
        '--regex',
        action='store_true',
        help='Explicitly treat the search pattern as a regular expression (default is literal).'
    )
    replace_parser.add_argument(
        '--non-interactive',
        action='store_true',
        help='Apply changes without asking for interactive confirmation.'
    )
    replace_parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Simulate changes and show a diff without modifying the file.'
    )
    replace_parser.add_argument(
        '--backup-dir',
        default='_archive',
        help='The directory to store backups in (default: _archive).'
    )
    replace_parser.add_argument(
        '--backup-strategy',
        choices=['simple', 'zip', 'tar'],
        default='zip',
        help='The backup strategy to use (default: zip).'
    )
    replace_parser.add_argument(
        '--max-backups',
        type=int,
        default=10,
        help='Maximum number of old backups to keep (default: 10, 0 for unlimited).'
    )
    replace_parser.add_argument(
        '--encoding',
        default='utf-8',
        help='Character encoding for the file (default: utf-8).'
    )
    replace_parser.add_argument(
        '--backup-level',
        choices=['simple', 'archive'],
        default='archive',
        help='Set the backup level.'
    )
    replace_parser.set_defaults(func=handle_replace)

    # Line operations command
    line_parser = subparsers.add_parser(
        'line',
        help='Perform line-level operations (insert, delete, replace).',
        description='Insert, delete, or replace specific lines in a file.'
    )
    line_parser.add_argument(
        'file_path',
        metavar='FILE',
        type=os.path.abspath,
        help='The path to the file to be edited.'
    )
    line_parser.add_argument(
        'line_operation',
        choices=['insert', 'delete', 'replace'],
        help='The line operation to perform.'
    )
    line_parser.add_argument(
        'line_number',
        type=int,
        help='The line number to operate on (1-indexed).'
    )
    line_parser.add_argument(
        '--content',
        help='Content to insert or replace (required for insert/replace).'
    )
    line_parser.add_argument(
        '--backup-dir',
        default='_archive',
        help='The directory to store backups in (default: _archive).'
    )
    line_parser.add_argument(
        '--backup-strategy',
        choices=['simple', 'zip', 'tar'],
        default='zip',
        help='The backup strategy to use (default: zip).'
    )
    line_parser.add_argument(
        '--max-backups',
        type=int,
        default=10,
        help='Maximum number of old backups to keep (default: 10, 0 for unlimited).'
    )
    line_parser.set_defaults(func=handle_line_operations)

    # Structured data command
    struct_parser = subparsers.add_parser(
        'structured',
        help='Manipulate structured data files (JSON, YAML, XML).',
        description='Get, set, or delete values in structured data files.'
    )
    struct_parser.add_argument(
        'file_path',
        metavar='FILE',
        type=os.path.abspath,
        help='The path to the structured data file to be edited.'
    )
    struct_parser.add_argument(
        'struct_operation',
        choices=['get', 'set', 'delete'],
        help='The structured data operation to perform.'
    )
    struct_parser.add_argument(
        '--key',
        required=True,
        help='The key/path to the value (e.g., "user.name" for nested values).'
    )
    struct_parser.add_argument(
        '--value',
        help='The value to set (required for set operation).'
    )
    struct_parser.add_argument(
        '--backup-dir',
        default='_archive',
        help='The directory to store backups in (default: _archive).'
    )
    struct_parser.add_argument(
        '--backup-strategy',
        choices=['simple', 'zip', 'tar'],
        default='zip',
        help='The backup strategy to use (default: zip).'
    )
    struct_parser.add_argument(
        '--max-backups',
        type=int,
        default=10,
        help='Maximum number of old backups to keep (default: 10, 0 for unlimited).'
    )
    struct_parser.set_defaults(func=handle_structured_data)

    # AST refactoring command
    refactor_parser = subparsers.add_parser(
        'refactor',
        help='Perform AST-based refactoring on Python files.',
        description='Rename or remove functions/classes in Python files using AST.'
    )
    refactor_parser.add_argument(
        'file_path',
        metavar='FILE',
        type=os.path.abspath,
        help='The path to the Python file to refactor.'
    )
    refactor_parser.add_argument(
        'refactor_operation',
        choices=['rename', 'remove'],
        help='The refactoring operation to perform.'
    )
    refactor_parser.add_argument(
        '--target',
        required=True,
        help='The function or class name to refactor.'
    )
    refactor_parser.add_argument(
        '--new-name',
        help='The new name (required for rename operation).'
    )
    refactor_parser.add_argument(
        '--backup-dir',
        default='_archive',
        help='The directory to store backups in (default: _archive).'
    )
    refactor_parser.add_argument(
        '--backup-strategy',
        choices=['simple', 'zip', 'tar'],
        default='zip',
        help='The backup strategy to use (default: zip).'
    )
    refactor_parser.add_argument(
        '--max-backups',
        type=int,
        default=10,
        help='Maximum number of old backups to keep (default: 10, 0 for unlimited).'
    )
    refactor_parser.set_defaults(func=handle_ast_refactor)

    # Comment operations command
    comment_parser = subparsers.add_parser(
        'comment',
        help='Perform code-aware comment operations.',
        description='Toggle comments on specific lines in code files.'
    )
    comment_parser.add_argument(
        'file_path',
        metavar='FILE',
        type=os.path.abspath,
        help='The path to the code file to edit.'
    )
    comment_parser.add_argument(
        'comment_operation',
        choices=['toggle_single'],
        help='The comment operation to perform.'
    )
    comment_parser.add_argument(
        '--line-number',
        type=int,
        required=True,
        help='The line number to comment/uncomment.'
    )
    comment_parser.add_argument(
        '--language',
        help='Programming language (auto-detected from file extension if not specified).'
    )
    comment_parser.add_argument(
        '--backup-dir',
        default='_archive',
        help='The directory to store backups in (default: _archive).'
    )
    comment_parser.add_argument(
        '--backup-strategy',
        choices=['simple', 'zip', 'tar'],
        default='zip',
        help='The backup strategy to use (default: zip).'
    )
    comment_parser.add_argument(
        '--max-backups',
        type=int,
        default=10,
        help='Maximum number of old backups to keep (default: 10, 0 for unlimited).'
    )
    comment_parser.set_defaults(func=handle_comment_operations)

    # Batch replace command
    batch_parser = subparsers.add_parser(
        'batch-replace',
        help='Find and replace text across multiple files.',
        description='Performs find-and-replace operations across multiple files.'
    )
    batch_parser.add_argument(
        '--pattern',
        required=True,
        help='The search pattern (regular expression).'
    )
    batch_parser.add_argument(
        '--replacement',
        required=True,
        help='The string to replace the pattern with.'
    )
    batch_parser.add_argument(
        '--files',
        nargs='+',
        help='Specific files to process.'
    )
    batch_parser.add_argument(
        '--glob-pattern',
        help='Glob pattern to match files (e.g., "*.py").'
    )
    batch_parser.add_argument(
        '--directory',
        help='Directory to search for files (used with --glob-pattern).'
    )
    batch_parser.add_argument(
        '--multiline', 
        action='store_true',
        help='Enable multiline matching (^ and $ match start/end of lines).'
    )
    batch_parser.add_argument(
        '--dotall',
        action='store_true',
        help='Make . match newline characters too.'
    )
    batch_parser.add_argument(
        '--ignore-case',
        action='store_true',
        help='Case-insensitive matching.'
    )
    batch_parser.add_argument(
        '--literal',
        action='store_true',
        help='Treat the search pattern as a literal string, not a regex.'
    )
    batch_parser.add_argument(
        '--backup-dir',
        default='_archive',
        help='The directory to store backups in (default: _archive).'
    )
    batch_parser.add_argument(
        '--backup-strategy',
        choices=['simple', 'zip', 'tar'],
        default='zip',
        help='The backup strategy to use (default: zip).'
    )
    batch_parser.add_argument(
        '--max-backups',
        type=int,
        default=10,
        help='Maximum number of old backups to keep (default: 10, 0 for unlimited).'
    )
    batch_parser.set_defaults(func=handle_batch_replace)

    # Undo command
    undo_parser = subparsers.add_parser(
        'undo',
        help='Restore a file from its most recent backup.',
        description='Restores a file from its most recent backup.'
    )
    undo_parser.add_argument(
        'file_path',
        metavar='FILE',
        type=os.path.abspath,
        help='The path to the file to restore.'
    )
    undo_parser.add_argument(
        '--backup-dir',
        default='_archive',
        help='The directory where backups are stored (default: _archive).'
    )
    undo_parser.set_defaults(func=handle_undo)

    # Safe Read command
    read_parser = subparsers.add_parser(
        'safe-read',
        help='Read content from a file with multiple modes and safety features.',
        description='Read content from a file using various modes: full, lines, bytes, or until_pattern.'
    )
    read_parser.add_argument(
        'file_path',
        metavar='FILE',
        type=os.path.abspath,
        help='The path to the file to be read.'
    )
    read_parser.add_argument(
        '--read-mode',
        choices=['full', 'lines', 'bytes', 'until_pattern'],
        default='full',
        help='The reading mode (default: full).'
    )
    read_parser.add_argument(
        '--encoding',
        default='utf-8',
        help='Character encoding for the file (default: utf-8).'
    )
    read_parser.add_argument(
        '--output-file',
        help='Path to write the read content (default: stdout or temp file if too large).'
    )
    read_parser.add_argument(
        '--start-line',
        type=int,
        help='For "lines" mode, the 0-based starting line number.'
    )
    read_parser.add_argument(
        '--num-lines',
        type=int,
        help='For "lines" mode, the number of lines to read.'
    )
    read_parser.add_argument(
        '--start-byte',
        type=int,
        help='For "bytes" mode, the 0-based starting byte offset.'
    )
    read_parser.add_argument(
        '--num-bytes',
        type=int,
        help='For "bytes" mode, the number of bytes to read.'
    )
    read_parser.add_argument(
        '--until-pattern',
        help='For "until_pattern" mode, a regex pattern to stop at.'
    )
    read_parser.add_argument(
        '--until-pattern-file',
        help='For "until_pattern" mode, path to a file containing a regex pattern.'
    )
    read_parser.add_argument(
        '--until-pattern-case-insensitive',
        action='store_true',
        help='For "until_pattern" mode, make search case-insensitive.'
    )
    read_parser.set_defaults(func=handle_safe_read)

    args = parser.parse_args()

    # Call the function associated with the chosen sub-command
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()