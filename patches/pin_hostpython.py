#!/usr/bin/env python3
"""Pin p4a's hostpython3 recipe to Python 3.10.13."""
import os
import re
import sys
import shutil

p4a_root = sys.argv[1] if len(sys.argv) > 1 else ".buildozer/android/platform/python-for-android"
recipe = os.path.join(p4a_root, "pythonforandroid/recipes/hostpython3/__init__.py")

print(f"P4A root: {p4a_root}")
print(f"Recipe: {recipe}")
assert os.path.exists(recipe), f"Recipe not found at {recipe}!"

with open(recipe) as f:
    content = f.read()

ver_match = re.search(r'version\s*=\s*"([^"]*)"', content)
print(f"Before: version = \"{ver_match.group(1)}\"")

content = re.sub(
    r'version\s*=\s*"[^"]*"',
    'version = "3.10.13"',
    content,
)
content = re.sub(
    r'url\s*=\s*"[^"]*"',
    'url = "https://www.python.org/ftp/python/{version}/Python-{version}.tar.xz"',
    content,
)

with open(recipe, "w") as f:
    f.write(content)

ver_match = re.search(r'version\s*=\s*"([^"]*)"', content)
print(f"After:  version = \"{ver_match.group(1)}\"")

# Clear __pycache__
cache = os.path.join(os.path.dirname(recipe), "__pycache__")
if os.path.exists(cache):
    shutil.rmtree(cache)
    print("Cleared recipe __pycache__")

print("SUCCESS: hostpython pinned to 3.10.13")
