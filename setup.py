import os
from setuptools import setup

# pyproject.toml is the source of truth for metadata and dependencies.
# This setup.py is kept for backwards compatibility with older pip versions.

scripts = []
scripts_dir = os.path.join(os.path.dirname(__file__), 'scripts')
if os.path.isdir(scripts_dir):
    for s in os.listdir(scripts_dir):
        if s != '.git':
            scripts.append('scripts/%s' % s)

setup(scripts=scripts)
