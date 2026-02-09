from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name="arpsurgeon",
    version="1.1.0",
    author="ARPSurgeon Contributors",
    description="Precision-oriented ARP observation and manipulation toolkit.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/ARPSurgeon",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    extras_require={
        "dev": ["pytest>=7.0", "httpx>=0.24"],
    },
    entry_points={
        "console_scripts": [
            "arpsurgeon=arpsurgeon.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
)
