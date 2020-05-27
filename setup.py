import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pysatochip", 
    version="0.11.a",
    author="Toporin",
    author_email="info@satochip.io",
    description="Simple python library to communicate with a Satochip hardware wallet",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Toporin/pysatochip",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)