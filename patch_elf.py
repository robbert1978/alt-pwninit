import argparse,subprocess
from pwn import ELF
from Libc import LIBC
def patch(bin: ELF,libc:LIBC,ld:ELF):
    get_file_name = lambda file_path: file_path.split("/")[-1]
    if get_file_name(libc.path) != "libc.so.6":
        subprocess.check_call(["/usr/bin/rm","-rf","./libc.so.6"],stderr=open("/tmp/pwninit_log","a+"))
        make_symlink=subprocess.check_call(["/bin/ln","-s","./{}".format(get_file_name(libc.path)),"libc.so.6"])
    run_patchelf=subprocess.check_call(
            ["/usr/bin/patchelf",
              "--set-rpath",".",
              "--set-interpreter","./{}".format(get_file_name(ld.path)),
              "--output","{}_patched".format(get_file_name(bin.path)),
              "./{}".format(get_file_name(bin.path)),        
            ],
            stderr=open("/tmp/pwninit_log","a+")
    )
    print("\nNew file: {}_patched".format(get_file_name(bin.path)))
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
    file_ld=ELF(args.ld,checksec=False) #Check ld is a valid ELF ?
    patch(file_bin,file_libc,file_ld)
if __name__=='__main__':
    main()
