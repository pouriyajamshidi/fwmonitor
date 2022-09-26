import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="fwmonitor",
    version="1.2.1",
    author="Pouriya Jamshidi",
    scripts=["fwmonitor"],
    description="for network traffic analysis, displays your iptables, UFW, or any application that logs in the same format, in a pleasant way.",
    long_description=long_description,
    long_description_content="text/markdown",
    python_requires=">=3.6",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
