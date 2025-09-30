#!/usr/bin/env bash
set -e
if [[ "$(basename "$PWD")" != "toutatis" ]] || [[ ! -f "r" ]] || [[ ! -f "s" ]]; then
    git clone https://github.com/zzryn/toutatis.git
    cd toutatis
fi
pip install -r r
python3 s install
clear
toutatis -h
