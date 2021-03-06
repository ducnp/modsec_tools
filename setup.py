from setuptools import setup, find_packages
from os import path
import io

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with io.open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='modsec_tools',
    version='0.2',
    description='Scripts to analyse logfiles and generate rule files for mod_security2.',
    long_description=long_description,
    url='https://github.com/zathras777/modsec_tools',
    author='david reid',
    author_email='zathrasorama@gmail.com',
    license='Unlicense',
    packages = find_packages(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
    ],
    keywords='apache security logfiles rules',
    entry_points={
        'console_scripts': ['analyse_audit=modsec_tools.analyse_audit:main',
                            'extract_rules=modsec_tools.extract_rules:main']

    },
)
