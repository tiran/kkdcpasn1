import glob
import os

from setuptools import setup
from setuptools.extension import Extension

try:
    from Cython.Build import cythonize
except ImportError:
    def cythonize(extensions, **kwargs):
        for extension in extensions:
            for i, filename in enumerate(extension.sources):
                if filename.endswith('.pyx'):
                    extension.sources[i] = filename[:-4] + '.c'
                    if not os.path.isfile(extension.sources[i]):
                        raise
        return extensions


extensions = [
    Extension(
        'kkdcpasn1',
        sources=['src/kkdcpasn1.pyx'] + glob.glob('src/asn1/*.c'),
        depends=['setup.py'] + glob.glob('src/asn1/*.h'),
        include_dirs=['src/asn1']
    ),
]

with open('README') as f:
    long_description = f.read()

setup(
    name='kkdcpasn1',
    description='High performance ASN.1 parser for Kerberos KDC Proxy [KKDCP]',
    long_description=long_description,
    keywords='asn1 kkdcp kerberos proxy',
    ext_modules=cythonize(extensions),
    version='0.3.dev1',
    license='MIT',
    author='Christian Heimes',
    author_email='cheimes@redhat.com',
    maintainer='Latchset Contributors',
    maintainer_email='cheimes@redhat.com',
    url='https://github.com/tiran/kkdcpasn1',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Cython',
        'Programming Language :: C',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    tests_require=['pytest'],
    extras_require={
        'test': ['pytest'],
        'test_docs': ['docutils', 'markdown'],
        'test_pep8': ['flake8', 'flake8-import-order', 'pep8-naming']
    },
)
