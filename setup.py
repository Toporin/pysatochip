import setuptools
import importlib.util
import shutil, os

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

# Copy satochip_cli into the module itself for packaging
shutil.copyfile("satochip_cli.py", "pysatochip/satochip_cli.py")

# load version.py; needlessly complicated alternative to "imp.load_source":
version_spec = importlib.util.spec_from_file_location('version', 'pysatochip/version.py')
version_module = version = importlib.util.module_from_spec(version_spec)
version_spec.loader.exec_module(version_module)

setuptools.setup(
    name="pysatochip", 
    version= version.PYSATOCHIP_VERSION,
    author="Toporin",
    author_email="satochip.wallet@gmail.com",
    description="Simple python library to communicate with a Satochip hardware wallet",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Toporin/pysatochip",
    project_urls={
        'Github': 'https://github.com/Toporin',
        'Webshop': 'https://satochip.io/',
        'Telegram': 'https://t.me/Satochip',
        'Twitter': 'https://twitter.com/satochip',
        'Source': 'https://github.com/Toporin/pysatochip/',
        'Tracker': 'https://github.com/Toporin/pysatochip/issues',
    },
    install_requires=requirements,
    extras_require={
        "CLI": ["mnemonic", "click", "websockets", "nostr", "cbor2"],
    },
    packages=setuptools.find_packages(),
    package_dir={
        'pysatochip': 'pysatochip'
    },
    package_data={
        'pysatochip': ['cert/*.cert'],
    },
    entry_points={"console_scripts": ["satochip-cli=pysatochip.satochip_cli:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)