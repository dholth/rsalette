# Starter SConstruct for enscons

import sys
from distutils import sysconfig
import pytoml as toml
import enscons

metadata = dict(toml.load(open('pyproject.toml')))['tool']['enscons']

full_tag = 'py2.py3-none-any' # pure Python packages compatible with 2+3

env = Environment(tools=['default', 'packaging', enscons.generate],
                  PACKAGE_METADATA=metadata,
                  WHEEL_TAG=full_tag,
                  ROOT_IS_PURELIB=full_tag.endswith('-any'))

# Only *.py is included automatically by setup2toml.
# Add extra 'purelib' files or package_data here.
py_source = ['rsalette.py'] + ['asn1lette.py']

purelib = env.Whl('purelib', py_source, root='')
whl = env.WhlFile(purelib)

# It's easier to just use Glob() instead of FindSourceFiles() since we have
# so few installed files..
sdist_source=File(['PKG-INFO', 'SConstruct', 'pyproject.toml']) \
        + Glob('*.py') + Glob('*.txt') + Glob('*.pem')
sdist = env.SDist(source=sdist_source)
env.NoClean(sdist)
env.Alias('sdist', sdist)

# needed for pep517 (enscons.api) to work
env.Default(whl, sdist)
