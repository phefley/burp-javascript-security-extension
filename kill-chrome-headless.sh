#!/bin/bash
for pid in `ps aux | grep chromium | grep headless | awk '{split($0,a," "); print a[2]}'`; do kill $pid;done
