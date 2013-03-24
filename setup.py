import os

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.txt')).read()
CHANGES = open(os.path.join(here, 'CHANGES.txt')).read()

tests_require = ["nose", "coverage"]

setup(name='rsalette',
      version='0.2.0',
      description='A pure-Python 2+3 RSA verification library.',
      long_description=README + '\n\n' +  CHANGES,
      classifiers=[
            "Topic :: Security :: Cryptography",
            "License :: OSI Approved :: Apache Software License",
        ],
      author='Daniel Holth',
      author_email='dholth@fastmail.fm',
      url='http://bitbucket.org/dholth/rsalette/',
      keywords='rsa',
      license='ASL 2',
      py_modules=['rsalette', 'asn1lette'],
      include_package_data=True,
      zip_safe=False,
      tests_require = tests_require,
      extras_require = dict(test=tests_require),
      test_suite = 'nose.collector',
      )
