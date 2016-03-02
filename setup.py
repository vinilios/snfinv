import os
from setuptools import setup, find_packages


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="snfinv",
    version="0.1.2",
    py_modules=['snfinv'],
    install_requires=['kamaki', 'pyfscache', 'pyyaml'],
    author="Kostas Papadimitriou",
    author_email="kpap@grnet.gr",
    license="GPL",
    keywords="ansible synnefo provision inventory",
    url="https://github.com/vinilios/snfinv",
    description="Dynamic ansible inventory for Synnefo IaaS nodes",
    long_description=read("README.rst"),
    entry_points={
        "console_scripts": [
            "snfinv = snfinv:main"
        ]
    }
)
