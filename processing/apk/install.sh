#!/usr/bin/env bash

git clone --recursive https://github.com/rednaga/yara-python-1 /tmp/yara-python && \
cd /tmp/yara-python && \
python setup.py build --enable-dex install && \
pip install apkid && \
rm -rf /tmp/yara-python

