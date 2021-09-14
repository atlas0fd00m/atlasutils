import sys
import os
from distutils.core import setup, Extension

packages = ['atlasutils', 'atlasutils.vtraceutils']
mods = []
pkgdata = {}
scripts = []
for s in os.listdir('scripts'):
    if s != '.git':
        scripts.append('scripts/%s'%s)


setup  (name        = 'atlasutils',
        version     = '3.0',
        description = 'atlas\' hacking toolbelt full of toys',
        author = 'atlas of d00m',
        author_email = 'atlas@r4780y.com',
        #include_dirs = ['psyco','PyElf-0.8',],
        packages  = packages,
        package_data = pkgdata,
        ext_modules = mods,
        scripts = scripts
       )
