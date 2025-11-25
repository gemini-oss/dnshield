#!/usr/bin/env python3
"""
Lint and fix manifest JSON files to prevent parsing errors.
This script detects and fixes common JSON issues that can cause validation failures.
"""

import json
import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional

class ManifestLinter:
    def __init__(self, fix: bool = False):
        self.fix = fix
        self.errors_found = []
        self.fixes_applied = []
        
    def detect_invisible_chars(self, content: str, filename: str) -> List[Tuple[int, str]]:
        """Detect invisible Unicode characters that can break JSON parsing."""
        issues = []
        invisible_chars = {
            '\u200b': 'zero-width space',
            '\u200c': 'zero-width non-joiner',
            '\u200d': 'zero-width joiner',
            '\ufeff': 'byte order mark',
            '\u202a': 'left-to-right embedding',
            '\u202b': 'right-to-left embedding',
            '\u202c': 'pop directional formatting',
            '\u202d': 'left-to-right override',
            '\u202e': 'right-to-left override',
            '\xa0': 'non-breaking space'
        }
        
        for char, name in invisible_chars.items():
            positions = [i for i, c in enumerate(content) if c == char]
            for pos in positions:
                issues.append((pos, f"Found {name} at position {pos}"))
                
        return issues
    
    def check_trailing_content(self, content: str) -> Optional[int]:
        """Check for content after the final closing brace."""
        # Find the last closing brace
        brace_count = 0
        last_closing_pos = -1
        
        for i, char in enumerate(content):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    last_closing_pos = i
                    
        if last_closing_pos != -1:
            # Check if there's any non-whitespace after the last closing brace
            remaining = content[last_closing_pos + 1:].strip()
            if remaining:
                return last_closing_pos + 1
                
        return None
    
    def validate_json_structure(self, content: str) -> Tuple[bool, Optional[str]]:
        """Validate JSON structure and return detailed error info."""
        try:
            json.loads(content)
            return True, None
        except json.JSONDecodeError as e:
            return False, f"JSON error at line {e.lineno}, column {e.colno}: {e.msg}"
    
    def fix_common_issues(self, content: str) -> str:
        """Fix common JSON issues."""
        original = content
        
        # Remove invisible Unicode characters
        invisible_chars = [
            '\u200b', '\u200c', '\u200d', '\ufeff', 
            '\u202a', '\u202b', '\u202c', '\u202d', '\u202e'
        ]
        for char in invisible_chars:
            if char in content:
                content = content.replace(char, '')
                self.fixes_applied.append(f"Removed invisible character: {repr(char)}")
        
        # Replace non-breaking spaces with regular spaces
        if '\xa0' in content:
            content = content.replace('\xa0', ' ')
            self.fixes_applied.append("Replaced non-breaking spaces")
        
        # Remove trailing commas before closing braces/brackets
        content = re.sub(r',(\s*[}\]])', r'\1', content)
        if content != original:
            self.fixes_applied.append("Removed trailing commas")
        
        # Ensure proper line endings
        content = content.replace('\r\n', '\n').replace('\r', '\n')
        
        # Remove any content after the final closing brace
        brace_count = 0
        for i, char in enumerate(content):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    # Found the final closing brace
                    remaining = content[i + 1:].strip()
                    if remaining:
                        content = content[:i + 1] + '\n'
                        self.fixes_applied.append(f"Removed trailing content: {repr(remaining[:50])}")
                    break
        
        return content
    
    def lint_file(self, filepath: Path) -> bool:
        """Lint a single manifest file."""
        print(f"\nChecking: {filepath}")
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Check for invisible characters
            invisible = self.detect_invisible_chars(content, str(filepath))
            if invisible:
                for pos, msg in invisible:
                    self.errors_found.append(f"{filepath}: {msg}")
                    print(f"  ⚠️  {msg}")
            
            # Check for trailing content
            trailing_pos = self.check_trailing_content(content)
            if trailing_pos is not None:
                msg = f"Non-whitespace content after JSON at position {trailing_pos}"
                self.errors_found.append(f"{filepath}: {msg}")
                print(f"  ⚠️  {msg}")
            
            # Validate JSON structure
            valid, error = self.validate_json_structure(content)
            if not valid:
                self.errors_found.append(f"{filepath}: {error}")
                print(f"  ❌ {error}")
                
                if self.fix:
                    # Try to fix common issues
                    fixed_content = self.fix_common_issues(content)
                    valid, _ = self.validate_json_structure(fixed_content)
                    
                    if valid:
                        # Also format the JSON nicely
                        data = json.loads(fixed_content)
                        fixed_content = json.dumps(data, indent=4, ensure_ascii=False)
                        
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(fixed_content)
                        print(f"  ✅ Fixed and saved")
                        return True
                    else:
                        print(f"  ❌ Could not automatically fix")
                        return False
            else:
                # Even if valid, apply fixes if requested
                if self.fix and (invisible or trailing_pos):
                    fixed_content = self.fix_common_issues(content)
                    data = json.loads(fixed_content)
                    fixed_content = json.dumps(data, indent=4, ensure_ascii=False)
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(fixed_content)
                    print(f"  ✅ Fixed minor issues and saved")
                    return True
                else:
                    print(f"  ✅ Valid JSON")
                    return True
                    
        except Exception as e:
            self.errors_found.append(f"{filepath}: {str(e)}")
            print(f"  ❌ Error: {str(e)}")
            return False
    
    def lint_directory(self, directory: Path) -> bool:
        """Lint all manifest files in a directory."""
        manifest_files = list(directory.rglob("*.json"))
        
        # Exclude index.json files
        manifest_files = [f for f in manifest_files if f.name != 'index.json']
        
        if not manifest_files:
            print("No manifest files found")
            return True
        
        print(f"Found {len(manifest_files)} manifest files")
        
        all_valid = True
        for filepath in manifest_files:
            if not self.lint_file(filepath):
                all_valid = False
        
        return all_valid

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Lint and fix manifest JSON files')
    parser.add_argument(
        'path',
        nargs='?',
        default='manifests',
        help='Path to manifest directory or file (default: manifests)'
    )
    parser.add_argument(
        '--fix',
        action='store_true',
        help='Automatically fix common issues'
    )
    parser.add_argument(
        '--check-only',
        action='store_true',
        help='Only check for issues, don\'t fix (default behavior)'
    )
    
    args = parser.parse_args()
    
    linter = ManifestLinter(fix=args.fix)
    path = Path(args.path)
    
    if path.is_file():
        success = linter.lint_file(path)
    elif path.is_dir():
        success = linter.lint_directory(path)
    else:
        print(f"Error: {path} not found")
        sys.exit(1)
    
    # Print summary
    print("\n" + "=" * 60)
    if linter.errors_found:
        print(f"❌ Found {len(linter.errors_found)} issue(s):")
        for error in linter.errors_found[:10]:  # Show first 10 errors
            print(f"  • {error}")
        if len(linter.errors_found) > 10:
            print(f"  ... and {len(linter.errors_found) - 10} more")
    
    if linter.fixes_applied:
        print(f"\n✅ Applied {len(set(linter.fixes_applied))} type(s) of fixes:")
        for fix in set(linter.fixes_applied):
            print(f"  • {fix}")
    
    if success and not linter.errors_found:
        print("🎉 All manifest files are clean!")
        sys.exit(0)
    elif linter.fix and linter.fixes_applied:
        print("\n✅ Fixed issues. Please run validation again to confirm.")
        sys.exit(0)
    else:
        if not args.fix:
            print("\n💡 Run with --fix to automatically fix these issues")
        sys.exit(1)

if __name__ == '__main__':
    main()