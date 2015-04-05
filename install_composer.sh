#!/bin/sh

if [ ! -f 'composer.phar' ]; then
    php -r "readfile('https://getcomposer.org/installer');" | php
else
    echo "already installed"
fi
