#!/usr/bin/env python3
"""
Setup script for Email Investigator - Forensic Edition
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="email-investigator",
    version="1.0.0",
    author="Forensic Analyst",
    author_email="analyst@example.com",
    description="A comprehensive email forensics analysis tool with modular architecture",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/forensic-analyst/email-investigator",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Legal Industry",
        "Topic :: Security :: Forensics",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "email-investigator=main:main",
        ],
    },
    package_data={
        "email_investigator": ["*.txt", "*.md"],
    },
    include_package_data=True,
    zip_safe=False,
)
