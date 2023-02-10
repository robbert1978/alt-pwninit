import os,pwn,sys
from check_requirement import *
def patch(bin: pwn.ELF,libc,ld):
    os.system(f"patchelf --replace-needed libc.so.6 {libc} --set-interpreter {ld} --output {bin.path}_patched {bin.path}")
    pwn.log.info(f"New file: {bin.path}_patched")
def main():
    if len(sys.argv)!=4:
        print(f"Usage: {sys.argv[0]} bin libc ld")
        exit(1)
    check_requirement()
    bin_path=sys.argv[1]
    libc=sys.argv[2]
    ld=sys.argv[3]
    patch(pwn.ELF(bin_path,checksec=0),libc,ld)
if __name__=='__main__':
    main()
