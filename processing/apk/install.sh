#!/usr/bin/env bash

source /fame/env/bin/activate && \
git clone --recursive https://github.com/rednaga/yara-python-1 /tmp/yara-python && \
cd /tmp/yara-python && \
python setup.py build --enable-dex install --force && \
pip install apkid && \
rm -rf /tmp/yara-python

