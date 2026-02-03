"""
Setup configuration for Shellcode Weaver package
LEGAL: Authorized security research and testing only
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="shellcode-weaver",
    version="4.0.0",
    author="Security Research Team",
    description="Ultimate Polymorphic Shellcode Engine - Authorized Research Only",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/shellcode-weaver",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Education",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "full": [
            "keystone-engine>=0.9.2",
            "capstone>=5.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "shellcode-weaver=shellcode_weaver.cli:main",
        ],
    },
    include_package_data=True,
)
