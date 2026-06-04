# Alt-pwninit

Auto getting linker, unstripping and getting the source codes of an Ubuntu or Debian GLibc.

## Setup

Python dependencies are declared in `pyproject.toml` and managed with
[uv](https://docs.astral.sh/uv/). Run `make setup` to install the system tools
(`patchelf`, `elfutils`), ensure `uv` is installed, and create the project `.venv`
(`uv sync`).

## Usage

`uv run` uses the project's `.venv`:

```sh
uv run pwninit.py -b ./chall -l ./libc.so.6
# convenience shortcut:
make run ARGS="-b ./chall -l ./libc.so.6"
```

### Run from anywhere

`make install` symlinks the `pwninit` wrapper into `~/.local/bin`, so you can run
it from any challenge directory (output files land in the current directory):

```sh
make install
pwninit -b ./chall -l ./libc.so.6
```

`Libc.py` can be used standalone too (`-ld` linker, `-u` unstrip, `-src` source):

```sh
uv run Libc.py ./libc.so.6 -ld -u
```

## Testing

`make test` runs a Docker-based test matrix: it pulls real libc binaries out of
Ubuntu/Debian images and checks that `Libc.py` can fetch the linker, unstrip the
libc, and recover symbols. Requires Docker.

```sh
make test                              # default Ubuntu + Debian matrix
make test ARGS="ubuntu:22.04 debian:12"  # specific images only
```