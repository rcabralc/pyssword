from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

# Sets __version__
version = {}
with open(path.join(here, 'version.py')) as f:
    exec(f.read(), version)

setup(
    name='pyssword',
    version=version['__version__'],
    description='A password generator',
    url='https://github.com/rcabralc/pgen',

    author='Rafael Cabral Coutinho',
    author_email='rcabralc@gmail.com',

    license='MIT',

    packages=find_packages('src'),
    package_dir={'': 'src'},

    install_requires=['docopt'],

    entry_points={
        'console_scripts': [
            'pyssword = pyssword:main'
        ]
    },
)
