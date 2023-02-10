import patch_elf
import unstrip_libc
import pwn,sys,os
required_tools=["7z","patchelf","eu-unstrip","wget","patchelf"]
def main():
    for tool in required_tools:
        if os.system(f"which {tool} 1>/dev/null"):
            raise Exception(f"Plz install {tool}")
    if (not pwn.args.BIN) and (not pwn.args.LIBC):
        print(f"""{sys.argv[0]} [OPTIONS]
OPTIONS:
[BIN=<Binary to pwn>]
[LIBC=<Challenge libc>]
[LD=<A linker to preload the libc> (Optional)]
""")
        exit(1)
    pwn.log.info(f"bin: {pwn.args.BIN}")
    pwn.log.info(f"libc: {pwn.args.LIBC}")
    bin_file=pwn.ELF(pwn.args.BIN,checksec=0)
    libc=unstrip_libc.LIBC(pwn.args.LIBC)
    if pwn.args.LD:
        ld=pwn.args.LD
        pwn.log.info(f"ld: {ld}")
    else:
        ld=unstrip_libc.get_linker(libc)
    unstrip_libc.unstrip(libc)
    patch_elf.patch(bin_file,libc.path,ld)
if __name__=='__main__':
    main()
