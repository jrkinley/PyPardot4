from setuptools import setup

setup(
    name="PyPardot4",
    version="1.2.0",
    author="James Kinley",
    author_email="jamesrobertkinley@gmail.com",
    license="MIT",
    description="API wrapper for APIv4 of Pardot marketing automation software.",
    keywords="pardot",
    url="https://github.com/jrkinley/PyPardot4",
    packages=['pypardot', 'pypardot.objects'],
    install_requires=['requests', 'pyjwt', 'cryptography'],
)
