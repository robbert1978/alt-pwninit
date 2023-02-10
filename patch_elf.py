import argparse,os
from pwn import ELF
from Libc import LIBC
def patch(bin: ELF,libc:LIBC,ld:ELF):
    run_patchelf=os.system(f"patchelf --replace-needed libc.so.6 {libc.path} --set-interpreter {ld.path} --output {bin.path}_patched {bin.path}")
    if run_patchelf:
        raise ValueError(f"patchelf return {run_patchelf}")
    print(f"New file: {bin}_patched")
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b","--bin",help="<Binary to pwn>")
    parser.add_argument("-l","--libc",help="<Challenge libc>")
    parser.add_argument("--ld",help="<A linker to preload the libc> (Optional)",default="/lib64/ld-linux-x86-64.so.2")
    args = parser.parse_args()
    if (not args.bin) or (not args.libc) :
        print(args.help)
        return 1
    file_bin=ELF(args.bin) #Check bin is a valid ELF ?
    file_libc=LIBC(args.libc)#Check bin is a valid LIBC ?
    file_ld=ELF(args.ld) #Check ld is a valid ELF ?
    patch(file_bin,file_libc,file_ld)
if __name__=='__main__':
    main()
