#!/bin/bash

source /fame/env/bin/activate && \
git clone --recursive https://github.com/VirusTotal/yara-python.git /tmp/yara-python && \
cd /tmp/yara-python && \
python setup.py build --enable-dex install && \
pip install apkid && \
rm -rf /tmp/yara-python

