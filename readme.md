# Alt-pwninit

Auto getting linker, unstripping and getting the source codes of an Ubuntu or Debian GLibc.

This script need some dependencies to work properly, Run `make setup` to install the prerequisites.

## Testing

`make test` runs a Docker-based test matrix: it pulls real libc binaries out of
Ubuntu/Debian images and checks that `Libc.py` can fetch the linker, unstrip the
libc, and recover symbols. Requires Docker.

```sh
make test                              # default Ubuntu + Debian matrix
make test ARGS="ubuntu:22.04 debian:12"  # specific images only
```