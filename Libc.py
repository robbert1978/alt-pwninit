import wget,os,random,shutil,argparse
from pyunpack import Archive
from pwn import ELF
pkd_url="https://launchpad.net/ubuntu/+archive/primary/+files/"
def find_Ubuntu_libc(path):
    f=open(path,"rb")
    long_version_string=f.read().split(b"GNU C Library (Ubuntu GLIBC ")[1].split(b")")[0].decode()
    f.close()
    return long_version_string
class LIBC(ELF):
#   Ex:  GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1)
#   "2.27-3ubuntu1" is long_version_string
#   "2.27" is short_version_string
	def __init__(self,path):
		super().__init__(path,checksec=0)
		
		try:
			self.long_version_string=find_Ubuntu_libc(path)
		except:
			raise Exception("Not Ubuntu GLIBC")
		if not (self.long_version_string):
			raise Exception("Not Ubuntu GLIBC")
		self.short_version_string=self.long_version_string.split("-")[0]
def fetch_file(working_dir: str,name_file: str):
    url="{}{}".format(pkd_url,name_file)
    wget.download(url,out="{}/{}".format(working_dir,name_file))
def extract_file(file_path,out_dir):
    Archive(file_path).extractall(out_dir)
def unstrip(libc: LIBC):
    id_=random.randint(1,50)
    working_dir=f"/tmp/unstrip_{id_}"
    if os.path.exists(working_dir):
        shutil.rmtree(working_dir)
    os.mkdir(working_dir)
    name_file_deb=f"libc6-dbg_{libc.long_version_string}_{libc.arch}.deb"
    fetch_file(working_dir,name_file_deb)
    extract_file("{}/{}".format(working_dir,name_file_deb),working_dir)
    unstripping_libc=os.system("eu-unstrip -o {} {} {}/usr/lib/debug/lib/x86_64-linux-gnu/libc-{}.so".format(
        libc.path,
        libc.path,
        working_dir,
        libc.short_version_string,
    ))
    if unstripping_libc:
        shutil.rmtree(working_dir)
        raise ValueError("eu-unstrip return {}".format(unstripping_libc))
    shutil.rmtree(working_dir)
def get_ld(libc: LIBC):
    id_=random.randint(50,100)
    working_dir="/tmp/get_ld_{}",format(id_)
    if os.path.exists(working_dir):
        shutil.rmtree(working_dir)
    os.mkdir(working_dir)
    name_file_deb="libc6_{}_{}.deb".format(libc.long_version_string,libc.arch)
    fetch_file(working_dir,name_file_deb)
    extract_file("{}/{}".format(working_dir,name_file_deb),working_dir)
    shutil.copy("{}/lib/x86_64-linux-gnu/ld-{}.so".format(
        working_dir,
        libc.short_version_string,
    ),".")
    shutil.rmtree(working_dir)
    return ELF("ld-{}.so".format(libc.short_version_string))
def getsrc(libc: LIBC):
    srcfile="glibc_{}.orig.tar.xz".format(libc.short_version_string)
    fetch_file(".",srcfile)
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("libc",metavar="<Libc file>")
    parser.add_argument("-u","--unstrip",help="Unstrip the libc file",action="store_true")
    parser.add_argument("-ld","--get_linker",help="Get the linker for libc",action="store_true")
    parser.add_argument("-src","--get_src",help="Get soruce code of libc",action="store_true")
    args=parser.parse_args()
    if not args.libc:
        print(args.help)
        return 1
    file_libc=LIBC(args.libc)
    if args.unstrip:
        unstrip(file_libc)
    if args.get_linker:
        get_ld(file_libc)
    if args.get_src:
        getsrc(file_libc)
if __name__=='__main__':
    main()

