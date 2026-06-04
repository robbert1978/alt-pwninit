.PHONY: setup test

setup:
	sudo apt install -y wget patchelf python3 python-is-python3 python3-pip elfutils
	sudo pip3 install wget pyunpack pwn patool --break-system-packages

# Docker-based test matrix: pulls real libc binaries and checks Libc.py can
# unstrip them and recover symbols. Pass images via ARGS, e.g.
#   make test ARGS="ubuntu:22.04 debian:12"
test:
	./test/tester.sh $(ARGS)
