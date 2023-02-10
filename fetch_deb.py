import os,pwn
from Libc import *
def fetch_deb(libc: LIBC,working_dir: str,file_deb: str):
	cmd=os.system(f"""
	rm -rf  {working_dir}
	mkdir {working_dir}
	wget  -O /tmp/{file_deb} {pkd_url}{file_deb}
	7z x /tmp/{file_deb} -o{working_dir} 1>/dev/null
	7z x {working_dir}/data.* -o{working_dir} 1>/dev/null
	sleep 1
	""")
	if cmd:
		raise Exception("Error when fetching deb")