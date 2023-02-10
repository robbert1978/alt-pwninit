import os,pwn,sys,random
from Libc import *
from fetch_deb import *
from check_requirement import *
def get_linker(libc: LIBC):
	pwn.log.info("Getting linker")
	id_=random.randint(50,100)
	working_dir=f"/tmp/{id_}"
	file_deb=f"libc6_{libc.name}_{libc.arch}.deb"
	pwn.log.info(f"Download {pkd_url}{file_deb}")
	fetch_deb(libc,working_dir,file_deb)
	cmd=os.system(f"""
	cp {working_dir}/lib/x86_64-linux-gnu/ld-{libc.version}.so .
	rm -rf {working_dir} 
	""")
	if cmd:
		raise Exception("Error when getting linker")
	return f"ld-{libc.version}.so" #linker name
def main():
	global libc
	check_requirement()
	if len(sys.argv)!=2:
		print(f"Usage: {sys.argv[0]} <libc_file>")
		exit(1)
	libc=LIBC(sys.argv[1])
	get_linker(libc)
if __name__=='__main__':
	main()
