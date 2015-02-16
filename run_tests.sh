#!/bin/bash

rm -rf tests/data/keychains/*/*
./vendor/bin/phpunit
