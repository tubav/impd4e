#!/bin/sh

# ---------------------
# Author: Jens Krenzin
# Version: 1.0
# Date: 15.3.2010
# ---------------------

echo ===== START OF SHELL-SCRIPT =====

mkdir impd4e-installation
cd impd4e-installation

echo ***** installing libpcap ... *****
sudo apt-get install libpcap-dev

echo ***** downloading libev ... *****
wget http://dist.schmorp.de/libev/libev-4.04.tar.gz
tar -xf libev-4.04.tar.gz

echo ***** installing libev ... *****
cd libev-4.04
./configure
make
sudo make install

echo ***** downloading libipfix ... *****
cd ..
git clone git://libipfix.git.sourceforge.net/gitroot/libipfix/libipfix
cd libipfix

echo ***** installing libipfix ... *****
./configure
make
sudo make install

echo ***** installing git ... *****
cd ..
sudo apt-get install git-core

echo ***** downloading impd4e ... *****
git clone git://impd4e.git.sourceforge.net/gitroot/impd4e/impd4e

echo ***** installing impd4e ... *****
cd impd4e
./configure
make
sudo make install

echo ***** deleting temporary folder *****
cd ..
cd ..
rm -rf impd4e-installation/

echo ===== END OF SHELL-SCRIPT =====
