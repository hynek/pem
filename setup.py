from setuptools import setup

import pem


setup(
    name='pem',
    version=pem.__version__,
    description='Parse and split PEM files painlessly.',
    long_description=(open('README.rst').read() + '\n\n' +
                      open('HISTORY.rst').read() + '\n\n' +
                      open('AUTHORS.rst').read()),
    url='http://github.com/hynek/pem/',
    license=pem.__license__,
    author=pem.__author__,
    author_email='hs@ox.cx',
    py_modules=['pem'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
