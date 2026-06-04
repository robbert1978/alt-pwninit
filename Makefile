.PHONY: setup install run test

BIN ?= $(HOME)/.local/bin

# Install the system tools the scripts call via subprocess (patchelf, eu-unstrip
# from elfutils), ensure uv is available, then create the project .venv from
# pyproject.toml.
setup:
	sudo apt install -y patchelf elfutils
	command -v uv >/dev/null 2>&1 || curl -LsSf https://astral.sh/uv/install.sh | sh
	uv sync

# Symlink the `pwninit` wrapper onto your PATH so you can run it anywhere.
install:
	mkdir -p $(BIN)
	ln -sf $(CURDIR)/pwninit $(BIN)/pwninit
	@echo "linked $(BIN)/pwninit -> $(CURDIR)/pwninit"
	@case ":$$PATH:" in *":$(BIN):"*) ;; *) echo "note: $(BIN) is not on your PATH; add it to run 'pwninit' everywhere" ;; esac

# Run the tool using the project's .venv, e.g.
#   make run ARGS="-b ./chall -l ./libc.so.6"
run:
	uv run pwninit.py $(ARGS)

# Docker-based test matrix: pulls real libc binaries and checks Libc.py can
# unstrip them and recover symbols. Pass images via ARGS, e.g.
#   make test ARGS="ubuntu:22.04 debian:12"
test:
	./test/tester.sh $(ARGS)
