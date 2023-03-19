import os,random,shutil,argparse,re,subprocess
import wget
from pyunpack import Archive
from pwn import ELF
import uuid
pkd_url="https://launchpad.net/ubuntu/+archive/primary/+files/"
def libcVersion(path) -> str:
    f=open(path,"rb")
    _=f.read()
    f.close()
    pattern = b"GLIBC (\d+\.\d+)-(\w+)"
    res = re.search(pattern, _)
    if res:
        majorVersion = res.group(1).decode()
        release      = res.group(2).decode()
        libcVersion = "{}-{}".format(majorVersion, release)
        return libcVersion
    else:
        return ""

class LIBC(ELF):
#   Ex:  GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1)
#   "2.27-3ubuntu1" is libcVersion
#   "2.27" is majorVersion 
    def __init__(self,path):
        super().__init__(path,checksec=0)
        self.libcVersion=libcVersion(path)
        if (self.libcVersion == ""):
            print("Ubuntu glibc not detected!")
            exit(1)
        self.majorVersion=self.libcVersion.split("-")[0]

def fetch_file(working_dir: str,name_file: str):
    url="{}{}".format(pkd_url,name_file)
    wget.download(url,out="{}/{}".format(working_dir,name_file))

def extract_file(file_path,out_dir):
    Archive(file_path).extractall(out_dir)

def unstrip(libc: LIBC):
    working_dir="/tmp/unstrip_{}".format(str(uuid.uuid4()))
    if os.path.exists(working_dir):
        shutil.rmtree(working_dir)
    os.mkdir(working_dir)
    libc6_dbg_deb="libc6-dbg_{}_{}.deb".format(libc.libcVersion,libc.arch)
    fetch_file(working_dir,libc6_dbg_deb)
    extract_file("{}/{}".format(working_dir,libc6_dbg_deb),working_dir)
    try:
        unstripping_libc=subprocess.check_call(
              ["/usr/bin/eu-unstrip",
               "-o",libc.path,
                libc.path, 
                "{}/usr/lib/debug/lib/{}-linux-gnu/libc-{}.so".format(
                    working_dir,
                    "x86_64" if libc.arch=="amd64" else "i386",
                    libc.majorVersion)
        ])
    except subprocess.CalledProcessError: #use build-id files method
        build_id=libc.buildid
        unstripping_libc=subprocess.check_call(
            ["/usr/bin/eu-unstrip",
              "-o",libc.path,
              libc.path, 
              "{}/usr/lib/debug/.build-id/{}/{}.debug".format(
                    working_dir,
                    build_id[:1].hex(), #build_id[0] is int
                    build_id[1:].hex()
              )
            ]
        )
        file_ld=get_ld(libc) #This method requires ld
    shutil.rmtree(working_dir)

def get_ld(libc: LIBC):
    working_dir="/tmp/get_ld_{}".format(str(uuid.uuid4()))
    if os.path.exists(working_dir):
        shutil.rmtree(working_dir)
    os.mkdir(working_dir)
    libc6_bin_deb="libc6_{}_{}.deb".format(libc.libcVersion,libc.arch)
    fetch_file(working_dir,libc6_bin_deb)
    extract_file("{}/{}".format(working_dir,libc6_bin_deb),working_dir)
    try: #cp ld binary
        shutil.copy("{}/lib/{}-linux-gnu/ld-{}.so".format(
            working_dir,
            "x86_64" if libc.arch=="amd64" else "i386",
            libc.majorVersion,
        ),".")
        file_ld=ELF("ld-{}.so".format(libc.majorVersion),checksec=0)
    except FileNotFoundError:
        shutil.copy("{}/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2".format(working_dir),".")
        file_ld=ELF("./ld-linux-x86-64.so.2",checksec=0)
    return file_ld

def unstrip_ld(libc: LIBC,file_ld :ELF):
    working_dir="/tmp/unstrip_{}".format(str(uuid.uuid4()))
    if os.path.exists(working_dir):
        shutil.rmtree(working_dir)
    os.mkdir(working_dir)
    libc6_dbg_deb="libc6-dbg_{}_{}.deb".format(libc.libcVersion,libc.arch)
    fetch_file(working_dir,libc6_dbg_deb)
    extract_file("{}/{}".format(working_dir,libc6_dbg_deb),working_dir)
    try: #unstrip ld binary
        unstripping_ld=subprocess.check_call(
            ["/usr/bin/eu-unstrip",
             "-o",file_ld.path,
             file_ld.path,
             "{}/usr/lib/debug/lib/{}-linux-gnu/ld-{}.so".format(
                working_dir,
                "x86_64" if libc.arch=="amd64" else "i386",
                libc.majorVersion)
            ]
        )
    except subprocess.CalledProcessError:
        ld_buildid=file_ld.buildid
        unstripping_ld=subprocess.check_call(
             ["/usr/bin/eu-unstrip",
             "-o",file_ld.path,
             file_ld.path,
             "{}/usr/lib/debug/.build-id/{}/{}.debug".format(
                working_dir,
                ld_buildid[:1].hex(),
                ld_buildid[1:].hex())
            ]
        )
        if unstripping_ld:
            shutil.rmtree(working_dir)
            raise ValueError("eu-unstrip return {}".format(unstripping_ld))
    shutil.rmtree(working_dir)

def getsrc(libc: LIBC):
    srcfile="glibc_{}.orig.tar.xz".format(libc.majorVersion)
    fetch_file(".",srcfile)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("libc",metavar="<Libc file>")
    parser.add_argument("-u","--unstrip",help="Unstrip the libc file",action="store_true")
    parser.add_argument("-ld","--get_linker",help="Get the linker for libc",action="store_true")
    parser.add_argument("-src","--get_src",help="Get soruce code of libc",action="store_true")
    args=parser.parse_args()
    if not args.libc:
        return 1
    file_libc=LIBC(args.libc)
    if args.unstrip:
        unstrip(file_libc)
    if args.get_linker:
        file_ld=get_ld(file_libc)
        unstrip_ld(file_libc,file_ld)
    if args.get_src:
        getsrc(file_libc)
if __name__=='__main__':
    main()
