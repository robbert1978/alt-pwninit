import os,pwn,sys,random
pkd_url="https://launchpad.net/ubuntu/+archive/primary/+files/"
required_tools=["7z","patchelf","eu-unstrip","wget"]
class LIBC(pwn.ELF):
	def __init__(self,path):
		super().__init__(path,checksec=0)
		f=open(path,"rb")
		try:
			self.name=f.read().split(b"GNU C Library (Ubuntu GLIBC ")[1].split(b")")[0].decode()
		except:
			raise Exception("Not Ubuntu GLIBC")
		if not (self.name):
			raise Exception("Not Ubuntu GLIBC")
		self.version=self.name.split("-")[0]
		f.close()
def unstrip(libc: LIBC):
	pwn.log.info("Unstripping libc")
	id_=random.randint(1,50)
	working_dir=f"/tmp/{id_}"
	file_deb=f"libc6-dbg_{libc.name}_{libc.arch}.deb"
	pwn.log.info(f"Download {pkd_url}{file_deb}")
	cmd=os.system(f"""
mkdir {working_dir}
wget -O /tmp/{file_deb} {pkd_url}{file_deb} 1>/dev/null 2>/dev/null
7z x /tmp/libc6-dbg_{libc.name}_{libc.arch}.deb -o/tmp/{id_}/ 1>/dev/null
7z x {working_dir}/data.* -o{working_dir} 1>/dev/null
eu-unstrip -o {libc.path} {libc.path} {working_dir}/usr/lib/debug/lib/x86_64-linux-gnu/libc-{libc.version}.so 
rm -rf {working_dir}
""")
	if cmd:
		raise Exception("Error")
def get_linker(libc: LIBC):
	pwn.log.info("Getting linker")
	id_=random.randint(50,100)
	working_dir=f"/tmp/{id_}"
	file_deb=f"libc6_{libc.name}_{libc.arch}.deb"
	pwn.log.info(f"Download {pkd_url}{file_deb}")
	cmd=os.system(f"""
mkdir {working_dir}
wget  -O /tmp/{file_deb} {pkd_url}{file_deb} 1>/dev/null 2>/dev/null
7z x /tmp/libc6_{libc.name}_{libc.arch}.deb -o{working_dir} 1>/dev/null
7z x {working_dir}/data.* -o/tmp/{id_}/ 1>/dev/null
cp {working_dir}/lib/x86_64-linux-gnu/ld-{libc.version}.so .
rm -rf {working_dir} 
""")
	if cmd:
		raise Exception("Error")
	return f"ld-{libc.version}.so" #linker name

def main():
	global libc
	if len(sys.argv)!=2:
		print(f"Usage: {sys.argv[0]} <libc_file>")
		exit(1)
	for tool in required_tools:
		if os.system(f"which {tool} 1>/dev/null"):
			raise Exception(f"Plz install {tool}")
	libc=LIBC(sys.argv[1])
	get_linker(libc)
	unstrip(libc)
if __name__=='__main__':
	main()
