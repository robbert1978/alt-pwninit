import pwn
pkd_url="https://launchpad.net/ubuntu/+archive/primary/+files/"
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