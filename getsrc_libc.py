from Libc import *
import os,pwn,sys
required_tools=["wget"]
def getsrc(libc: LIBC):
    pwn.log.info("Getting glibc source code")
    pwn.log.info(f"Download {pkd_url}glibc_{libc.version}.orig.tar.xz")
    cmd=os.system(f"wget {pkd_url}glibc_{libc.version}.orig.tar.xz")
    if cmd:
        raise Exception("Error when downloading")
    pwn.log.info(f"File: glibc_{libc.version}.orig.tar.xz")
def main():
	global libc
	if len(sys.argv)!=2:
		print(f"Usage: {sys.argv[0]} <libc_file>")
		exit(1)
	for tool in required_tools:
		if os.system(f"which {tool} 1>/dev/null"):
			raise Exception(f"Plz install {tool}")
	libc=LIBC(sys.argv[1])
	getsrc(libc)
if __name__=='__main__':
	main()

