#!/usr/bin/env bash

git clone --recursive https://github.com/rednaga/yara-python-1 yara-python && \
cd yara-python && \
python setup.py build --enable-dex install && \
pip install apkid && \
rm -rf yara-python

