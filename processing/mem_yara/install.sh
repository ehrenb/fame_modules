#!/usr/bin/env bash

# pip install yara-python --global-option="build_ext" --global-option="--enable-dex"
git clone --recursive https://github.com/rednaga/yara-python-1 yara-python
cd yara-python
python setup.py build --enable-dex install