#!/bin/bash
VERSION=$(curl https://chromedriver.storage.googleapis.com/LATEST_RELEASE_$1)
wget https://chromedriver.storage.googleapis.com/$VERSION/chromedriver_linux64.zip
