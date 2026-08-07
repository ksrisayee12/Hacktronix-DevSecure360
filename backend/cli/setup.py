from setuptools import setup, find_packages

setup(
    name="devsecure",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "typer[all]",
        "rich",
        "prompt_toolkit"
    ],
    entry_points={
        "console_scripts": [
            "devsecure=cli.main:main",
        ],
    },
)
