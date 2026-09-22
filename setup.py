import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="sqlinja",
    version="0.3.0",
    author="CybCorv",
    author_email="jb.astarie@ordanchesolutions.fr",
    description="SqlInja is a Python library designed to automate exploitation of SQL blind injection (time-based or boolean-based).",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CybCorv/sqlinja",
    license="MIT",
    packages=setuptools.find_packages(exclude=["tests", "tests.*", "examples", "examples.*"]),
    package_data={"sqlinja": ["py.typed"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Typing :: Typed",
    ],
    # PEP 604 unions and typing.Protocol are used throughout
    python_requires=">=3.10",
)