import patch_elf,Libc,argparse
from pwn import ELF
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b","--bin",help="<Binary to pwn>")
    parser.add_argument("-l","--libc",help="<Challenge libc>")
    parser.add_argument("--ld",help="<A linker to preload the libc> (Optional)")
    args = parser.parse_args()
    if (not args.bin) or (not args.libc) :
        print(args.help)
        return 1
    file_bin=ELF(args.bin)  #Check bin is a valid ELF ?
    file_libc=Libc.LIBC(args.libc) #Check bin is a valid LIBC ?
    if args.ld:
        file_ld=ELF(args.ld)
    else:
        file_ld=Libc.get_ld(file_libc)
    patch_elf.patch(file_bin,file_libc,file_ld)

if __name__=='__main__':
    main()
