import setuptools

from ldif2bloodhound import __version__, description

setuptools.setup(
    name='ldif2bloodhound',
    version=__version__,
    author='Adrian Vollmer',
    author_email='adrian.vollmer@syss.de',
    description=description,
    long_description=open('README.md', 'r').read(),
    long_description_content_type='text/markdown',
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': [
            'ldif2bloodhound=ldif2bloodhound.__main__:main'
        ],
    },
    install_requires=[
        'ldif',
        'adexplorersnapshot@git+https://github.com/AdrianVollmer/ADExplorerSnapshot.py.git',
    ],
    python_requires='>=3.7',
    tests_require=[
        'pytest',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
)
