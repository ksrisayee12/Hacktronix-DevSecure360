"""
DevSecure360 — CLI Package Setup
Installs the `devsecure` command-line tool.

Usage:
    pip install -e .
    devsecure
"""

from setuptools import setup, find_packages

setup(
    name="devsecure360-cli",
    version="1.0.0",
    description="DevSecure360 — AI-Powered Application Security CLI",
    author="DevSecure360 Team",
    packages=find_packages(exclude=["frontend", "*.egg-info"]),
    install_requires=[
        # CLI Framework
        "typer>=0.12.0",
        "rich>=13.7.0",
        "prompt-toolkit>=3.0.43",
        # File Monitoring & Git
        "watchdog>=4.0.0",
        "gitpython>=3.1.43",
        # Config & Utilities
        "tomli>=2.0.1; python_version < '3.11'",
        "tomli-w>=1.0.0",
        # Already in backend/requirements.txt but needed explicitly here
        "python-dotenv>=1.0.0",
        "pyyaml>=6.0",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "devsecure=cli.main:main",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
    ],
)
