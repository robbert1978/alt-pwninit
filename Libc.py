import os
import random
import shutil
import argparse
import re
import json
import urllib.request
import subprocess
import wget
from pyunpack import Archive
from pwn import ELF
import uuid
import patoolib

# Ubuntu keeps a flat archive of every published file here.
pkd_url = "https://launchpad.net/ubuntu/+archive/primary/+files"
# Debian historical packages are resolved through the snapshot service.
snapshot_url = "https://snapshot.debian.org"


def libcVersion(path) -> tuple:
    f = open(path, "rb")
    _ = f.read()
    f.close()
    #   Ex (Ubuntu): GLIBC 2.27-3ubuntu1   -> release "3ubuntu1"
    #   Ex (Debian): GLIBC 2.31-13+deb11u5 -> release "13+deb11u5"
    pattern = b"(Ubuntu|Debian) GLIBC ([0-9]+[.][0-9]+)-([^)]+)"
    res = re.search(pattern, _)
    if res:
        distro = res.group(1).decode()
        libcVersion = res.group(2).decode()
        releaseNumber = res.group(3).decode()
        return (distro, libcVersion, releaseNumber)
    else:
        return ("", "", "")


def extract(archive: str, extractPath: str, extractFiles: tuple = ()):
    try:
        Archive(archive).extractall(extractPath)
    except:
        print("err: extract()")
        exit(1)


class LIBC(ELF):
    #   Ex:  GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1)
    #   "Ubuntu" is distro
    #   "2.27" is libcVersion
    #   "3ubuntu1" is releaseNumber
    def __init__(self, path):
        super().__init__(path, checksec=0)
        self.distro, self.libcVersion, self.releaseNumber = libcVersion(path)
        if (self.libcVersion == ""):
            print("Ubuntu/Debian glibc not detected!")
            exit(1)
        self.libc6_bin_deb = "libc6_{}-{}_{}.deb".format(
            self.libcVersion, self.releaseNumber, self.arch)
        self.libc6_dbg_deb = "libc6-dbg_{}-{}_{}.deb".format(
            self.libcVersion, self.releaseNumber, self.arch)
        self.workDir = "/tmp/pwninit_{}".format(str(uuid.uuid4()))
        self.dbgSym = "{}/dbgsym".format(self.workDir)
        self.libcBin = "{}/libcbin".format(self.workDir)
        if os.path.exists(self.workDir):
            shutil.rmtree(self.workDir)
        os.mkdir(self.workDir)

    def __del__(self):
        if os.path.exists(self.workDir):
            shutil.rmtree(self.workDir)

    def debUrl(self, debName) -> str:
        # Resolve the download URL of a .deb for the detected distro.
        if self.distro == "Ubuntu":
            return "{}/{}".format(pkd_url, debName)
        # Debian: look the file up on snapshot.debian.org by package/version,
        # then download it by its content hash.
        pkg = "libc6-dbg" if "dbg" in debName else "libc6"
        version = "{}-{}".format(self.libcVersion, self.releaseNumber)
        api = "{}/mr/binary/{}/{}/binfiles?fileinfo=1".format(
            snapshot_url, pkg, version)
        try:
            with urllib.request.urlopen(api) as resp:
                data = json.loads(resp.read())
        except Exception:
            print("err: can't query snapshot.debian.org for {}".format(debName))
            exit(1)
        for entry in data.get("result", []):
            if entry["architecture"] == self.arch:
                return "{}/file/{}".format(snapshot_url, entry["hash"])
        print("err: no Debian {} package for arch {}".format(pkg, self.arch))
        exit(1)

    def downloadDeb(self, debName, archive):
        # Download a .deb into the work dir, skipping if already present.
        if not os.path.exists(archive):
            wget.download(self.debUrl(debName), archive)

    def getLinker(self, path=".") -> ELF:
        # get ld binary
        archive = "{}/{}".format(self.workDir, self.libc6_bin_deb)
        self.downloadDeb(self.libc6_bin_deb, archive)
        _ = self.libcBin

        if not os.path.exists(_):
            os.mkdir(_)
            extract(archive, _)

        try:

            if self.arch == "amd64":

                linkerPath = "{}/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2".format(
                    _)

                if not os.path.exists(linkerPath):
                    linkerPath = "{}/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2".format(
                        _)

                if not os.path.exists(linkerPath):
                    raise FileNotFoundError

                ELF(linkerPath, checksec=False)
                shutil.copy(linkerPath, path)
                linker = ELF("{}/ld-linux-x86-64.so.2".format(path),
                             checksec=False)

            elif self.arch == "i386":

                linkerPath = "{}/lib/i386-linux-gnu/ld-linux.so.2".format(
                    _)

                if not os.path.exists(linkerPath):
                    linkerPath = "{}/usr/lib/i386-linux-gnu/ld-linux.so.2".format(
                        _)

                if not os.path.exists(linkerPath):
                    raise FileNotFoundError

                ELF(linkerPath, checksec=False)
                shutil.copy(linkerPath, path)
                linker = ELF("{}/ld-linux.so.2".format(path),
                             checksec=False)

        except FileNotFoundError:
            print("err: Can't find the linkerfile")
            exit(1)

        archive = "{}/{}".format(self.workDir, self.libc6_dbg_deb)
        self.downloadDeb(self.libc6_dbg_deb, archive)

        _ = self.dbgSym
        if not os.path.exists(_):
            os.mkdir(_)
            extract(archive, _)
        # try unstrip the linkerfile
        try:
            _ = subprocess.check_call(
                [
                    "/usr/bin/eu-unstrip",
                    "-o", linker.path,
                    linker.path,
                    "{}/usr/lib/debug/lib/{}-linux-gnu/ld-{}.so".format(
                        self.dbgSym,
                        "x86_64" if self.arch == "amd64" else "i386",
                        self.libcVersion
                    )
                ],
                stderr=open("/tmp/pwninit_log", "a+")
            )
        except subprocess.CalledProcessError:
            _ = subprocess.check_call(
                [
                    "/usr/bin/eu-unstrip",
                    "-o", linker.path,
                    linker.path,
                    "{}/usr/lib/debug/.build-id/{}/{}.debug".format(
                        self.dbgSym,
                        linker.buildid[:1].hex(),
                        linker.buildid[1:].hex()
                    )
                ],
                stderr=open("/tmp/pwninit_log", "a+")
            )
        if _:
            print("err {}: eu-unstrip".format(_))
            exit(1)
        return linker

    def unstripLibc(self):
        archive = "{}/{}".format(self.workDir, self.libc6_dbg_deb)
        self.downloadDeb(self.libc6_dbg_deb, archive)

        _ = self.dbgSym
        if not os.path.exists(_):
            os.mkdir(_)
            extract(archive, _)

        try:
            _ = subprocess.check_call(
                [
                    "/usr/bin/eu-unstrip",
                    "-o", self.path,
                    self.path,
                    "{}/usr/lib/debug/lib/{}-linux-gnu/libc-{}.so".format(
                        self.dbgSym,
                        "x86_64" if self.arch == "amd64" else "i386",
                        self.libcVersion
                    )
                ],
                stderr=open("/tmp/pwninit_log", "a+")
            )
        except subprocess.CalledProcessError:
            _ = subprocess.check_call(
                [
                    "/usr/bin/eu-unstrip",
                    "-o", self.path,
                    self.path,
                    "{}/usr/lib/debug/.build-id/{}/{}.debug".format(
                        self.dbgSym,
                        self.buildid[:1].hex(),
                        self.buildid[1:].hex()
                    )
                ],
                stderr=open("/tmp/pwninit_log", "a+")
            )
        if _:
            print("err {}: eu-unstrip".format(_))
            exit(1)

    def getSrc(self):
        srcName = "glibc_{}.orig.tar.xz".format(self.libcVersion)
        if self.distro == "Ubuntu":
            wget.download(
                "http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/{}".format(srcName))
            return
        # Debian: locate the upstream orig tarball on snapshot.debian.org.
        version = "{}-{}".format(self.libcVersion, self.releaseNumber)
        api = "{}/mr/package/glibc/{}/srcfiles?fileinfo=1".format(
            snapshot_url, version)
        try:
            with urllib.request.urlopen(api) as resp:
                data = json.loads(resp.read())
        except Exception:
            print("err: can't query snapshot.debian.org for glibc source")
            exit(1)
        for h, files in data.get("fileinfo", {}).items():
            for f in files:
                if f["name"] == srcName:
                    wget.download("{}/file/{}".format(snapshot_url, h), srcName)
                    return
        print("err: can't find glibc source {}".format(srcName))
        exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("libc", metavar="<Libc file>")
    parser.add_argument("-u", "--unstrip",
                        help="Unstrip the libc file", action="store_true")
    parser.add_argument("-ld", "--get_linker",
                        help="Get the linker for libc", action="store_true")
    parser.add_argument("-src", "--get_src",
                        help="Get soruce code of libc", action="store_true")
    args = parser.parse_args()
    if not args.libc:
        return 1
    libcObject = LIBC(args.libc)
    if args.unstrip:
        libcObject.unstripLibc()
    if args.get_linker:
        libcObject.getLinker()
    if args.get_src:
        libcObject.getSrc()


if __name__ == '__main__':
    main()
