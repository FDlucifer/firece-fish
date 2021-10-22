from setuptools import setup
from setuptools import find_packages


version = '1.0.0'

with open('requirements.txt') as f:
    requires = f.read().splitlines()

setup(
    name = "osprey",
    version=version,
    description='osprey PoC-framework',
    long_description='osprey is a vulnerability detecting tool for pentester.',
    author='lUc1f3r11',
    author_email='yang.wang@tophant.com',
    url='https://fdlucifer.github.io/',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=requires,
)
