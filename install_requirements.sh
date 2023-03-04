#!/bin/sh
cat ./requirements.system | xargs sudo apt install -y
sudo pip install -r ./requirements.txt