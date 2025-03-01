from setuptools import setup, find_packages
from pathlib import Path

VERSION = "0.0.0"
DESCRIPTION = "ProGen"
this_directory = Path(__file__).parent


# Setting up
setup(
    # the name must match the folder name 'verysimplemodule'
    name="ProGen",
    version=VERSION,
    description=DESCRIPTION,
    packages=find_packages(),
    install_requires=[
        "torch",
        "tensorboard",
        "opacus",
        "tqdm",
        "matplotlib",
        "pandas",
        "scikit-learn",
        "more-itertools",
        "gensim==3.8.3",
        "networkx",
        "notebook",
        "ipyplot",
        "jupyterlab",
        "statsmodels",
        "gdown",
        "annoy",
        "pyshark",
        "scapy",
        "ray",
        "ray[default]",
        "multiprocess",
        "addict",
        "config_io==0.4.0",
        "flask",
    ],  # add any additional packages that
    # needs to be installed along with your package. Eg: 'caer'
    keywords=["python", "netshare"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Education",
        "Programming Language :: Python :: 3.9",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux"
    ],
)
