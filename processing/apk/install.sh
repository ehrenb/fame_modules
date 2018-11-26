#!/usr/bin/env bash


pip install yara-python --global-option="build_ext" --global-option="--enable-dex" &&\
pip install apkid --no-deps