import os,random,shutil,argparse,re,subprocess
import wget
from pyunpack import Archive
from pwn import ELF
import uuid
import patoolib

pkd_url="https://launchpad.net/ubuntu/+archive/primary/+files"

def libcVersion(path) -> tuple:
    f=open(path,"rb")
    _=f.read()
    f.close()
    pattern = b"GLIBC (\d+\.\d+)-(\w+\d+(?:\.\d+)?)?"
    res = re.search(pattern, _)
    if res:
        libcVersion = res.group(1).decode()
        releaseNumber      = res.group(2).decode()
        return (libcVersion, releaseNumber)
    else:
        return ""

def extract(archive: str, extractPath: str, extractFiles: tuple = ()):
    try:
        Archive(archive).extractall(extractPath)
    except:
        print("err: extract()")
        exit(1)

class LIBC(ELF):
#   Ex:  GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1)
#   "2.27" is libcVersion
#   "3ubuntu1" is releaseNumber 
    def __init__(self,path):
        super().__init__(path,checksec=0)
        self.libcVersion, self.releaseNumber = libcVersion(path)
        if (self.libcVersion == ""):
            print("Ubuntu glibc not detected!")
            exit(1)
        self.libc6_bin_deb = "libc6_{}-{}_{}.deb".format(self.libcVersion,self.releaseNumber,self.arch)
        self.libc6_dbg_deb = "libc6-dbg_{}-{}_{}.deb".format(self.libcVersion,self.releaseNumber,self.arch)
        self.workDir = "/tmp/pwninit_{}".format(str(uuid.uuid4()))
        self.dbgSym = "{}/dbgsym".format(self.workDir)
        self.libcBin = "{}/libcbin".format(self.workDir)
        if os.path.exists(self.workDir):
            shutil.rmtree(self.workDir)
        os.mkdir(self.workDir)

    def __del__(self):
        if os.path.exists(self.workDir):
            shutil.rmtree(self.workDir)

    def getLinker(self, path = ".") -> ELF:
        #get ld binary
        _ = "{}/{}".format(pkd_url, self.libc6_bin_deb)
        archive = "{}/{}".format(self.workDir, self.libc6_bin_deb)
        wget.download(
            _,
            archive)
        _ = self.libcBin

        if not os.path.exists(_):
            os.mkdir(_)
            extract(archive, _)

        linkerPath = "{}/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2".format(_)

        try:
            ELF(linkerPath, checksec=False)
            shutil.copy(linkerPath, path)
            linker=ELF("{}/ld-linux-x86-64.so.2".format(path),checksec=False)
        except FileNotFoundError:
            print("err: Can't find the linkerfile")
            exit(1)

        _ = "{}/{}".format(pkd_url, self.libc6_dbg_deb)
        archive = "{}/{}".format(self.workDir, self.libc6_dbg_deb)
        if not os.path.exists(archive):
            wget.download(
                _,
                archive)
        
        _ = self.dbgSym
        if not os.path.exists(_):
            os.mkdir(_)
            extract(archive, _)
        #try unstrip the linkerfile
        try:
            cmd = "/usr/bin/eu-unstrip -o {} {} {}/usr/lib/debug/lib/{}-linux-gnu/ld-{}.so".format(
                linker.path,
                linker.path,
                self.dbgSym,
                "x86_64" if self.arch=="amd64" else "i386",
                self.libcVersion
            )
            _=subprocess.check_call(
                cmd.split()
            )
        except subprocess.CalledProcessError:
            cmd = "/usr/bin/eu-unstrip -o {} {} {}/usr/lib/debug/.build-id/{}/{}.debug".format(
                linker.path,
                linker.path,
                self.dbgSym,
                linker.buildid[:1].hex(),
                linker.buildid[1:].hex()
            )
            _=subprocess.check_call(
                cmd.split()
            )
        if _:
            print("err {}: eu-unstrip".format(_))
            exit(1)
        return linker
    def unstripLibc(self):
        archive = "{}/{}".format(self.workDir, self.libc6_dbg_deb)
        if not os.path.exists(archive):
            wget.download(
                _,
                archive)
        
        _ = self.dbgSym
        if not os.path.exists(_):
            os.mkdir(_)
            extract(archive, _)

        try:
            cmd = "/usr/bin/eu-unstrip -o {} {} {}/usr/lib/debug/lib/{}-linux-gnu/libc-{}.so".format(
                self.path,
                self.path,
                self.dbgSym,
                "x86_64" if self.arch=="amd64" else "i386",
                self.libcVersion
            )
            _=subprocess.check_call(
                cmd.split()
            )
        except subprocess.CalledProcessError:
            cmd = "/usr/bin/eu-unstrip -o {} {} {}/usr/lib/debug/.build-id/{}/{}.debug".format(
                self.path,
                self.path,
                self.dbgSym,
                self.buildid[:1].hex(),
                self.buildid[1:].hex()
            )
            _=subprocess.check_call(
                cmd.split()
            )
        if _:
            print("err {}: eu-unstrip".format(_))
            exit(1)

    def getSrc(self):
        wget.download("glibc_{}.orig.tar.xz".format(self.libcVersion))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("libc",metavar="<Libc file>")
    parser.add_argument("-u","--unstrip",help="Unstrip the libc file",action="store_true")
    parser.add_argument("-ld","--get_linker",help="Get the linker for libc",action="store_true")
    parser.add_argument("-src","--get_src",help="Get soruce code of libc",action="store_true")
    args=parser.parse_args()
    if not args.libc:
        return 1
    libcObject=LIBC(args.libc)
    if args.unstrip:
        libcObject.unstripLibc()
    if args.get_linker:
        libcObject.getLinker()
    if args.get_src:
        libcObject.getSrc()

if __name__=='__main__':
    main()
