from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="gavel-verify",
    version="0.1.0",
    author="Gavel Team",
    description="AI-powered vulnerability report verification tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/gavel",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    install_requires=[
        "anthropic>=0.39.0",
        "openai>=1.54.0",
        "requests>=2.31.0",
        "python-dotenv>=1.0.0",
        "click>=8.1.7",
        "rich>=13.7.0",
        "GitPython>=3.1.40",
        "pygments>=2.17.2",
        "aiohttp>=3.9.1",
        "pydantic>=2.5.3",
        "tenacity>=8.2.3",
    ],
    entry_points={
        "console_scripts": [
            "gavel=gavel.cli:main",
        ],
    },
)
