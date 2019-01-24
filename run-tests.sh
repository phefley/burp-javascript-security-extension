#!/bin/bash
sudo systemd-resolve --flush-caches
./gradlew -b tests.gradle clean test
