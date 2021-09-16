import os
import sys
from setuptools import find_packages, setup

VERSION = '3.0.2'
desc = 'atlas\' hacking toolbelt full of toys'

mods = []
pkgdata = {'vivscripts': ['vivscripts/*']}

scripts = []
for s in os.listdir('scripts'):
    if s != '.git':
        scripts.append('scripts/%s'%s)


setup  (name        = 'atlasutils',
        version     = VERSION,
        description = desc,
        long_description=desc,
        long_description_content_type='text/markdown',
        author = 'atlas of d00m',
        author_email = 'atlas@r4780y.com',
        url = 'https://github.com/atlas0fd00m/atlasutils',
        packages = find_packages(),
        package_data = pkgdata,
        ext_modules = mods,
        scripts = scripts
       )
