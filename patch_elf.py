import argparse,os
from pwn import ELF
from Libc import LIBC
def patch(bin: ELF,libc:LIBC,ld:ELF):
    run_patchelf=os.system("""
	patchelf \
	--replace-needed libc.so.6 {} \
	--set-interpreter {} \
	--output {}_patched \
	{} 2>/dev/null""".format(
        libc.path,
        ld.path,
        bin.path,
        bin.path
    ))
    if run_patchelf:
        raise ValueError("patchelf return {}".format(run_patchelf))
    print("\nNew file: {}_patched".format(bin.path))
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b","--bin",metavar="<Bin file>",help="<Binary to pwn>",required=True)
    parser.add_argument("-l","--libc",metavar="<Libc file>",help="<Challenge libc>",required=True)
    parser.add_argument("--ld",help="<A linker to preload the libc> (Optional)",default="/lib64/ld-linux-x86-64.so.2")
    args = parser.parse_args()
    if (not args.bin) or (not args.libc) :
        return 1
    file_bin=ELF(args.bin) #Check bin is a valid ELF ?
    file_libc=LIBC(args.libc)#Check bin is a valid LIBC ?
    file_ld=ELF(args.ld,checksec=0) #Check ld is a valid ELF ?
    patch(file_bin,file_libc,file_ld)
if __name__=='__main__':
    main()
