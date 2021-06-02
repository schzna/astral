#include "astral.h"
#include "elf.h"
#include "x86.h"

void out_elf64()
{
    int load_address = 0x400000;
    char *str = "Hello\n";
    //char *code = "\x48\xc7\xc0\x01\x00\x00\x00\x48\xc7\xc7\x01\x00\x00\x00\x48\xc7\xc6\x78\x00\x40\x00\x48\xc7\xc2\x06\x00\x00\x00\x0f\x05\x48\xc7\xc0\x3c\x00\x00\x00\x0f\x05";
    int code_len = code_index;
    int string_len = strlen(str);
    Elf64_Ehdr ehdr = {
        .e_ident = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
                    ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_SYSV},
        .e_type = ET_EXEC,
        .e_machine = EM_X86_64,
        .e_version = EV_CURRENT,
        .e_entry = load_address + sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) + string_len,
        .e_phoff = sizeof(Elf64_Ehdr),
        .e_shoff = 0, // dummy
        .e_flags = 0x0,
        .e_ehsize = sizeof(Elf64_Ehdr),
        .e_phentsize = sizeof(Elf64_Phdr),
        .e_phnum = 1,
        .e_shentsize = 0, // dummy
        .e_shnum = 0,
        .e_shstrndx = 0, // dummy
    };

    Elf64_Phdr phdr = {
        .p_type = PT_LOAD,
        .p_offset = 0x0,
        .p_vaddr = load_address,
        .p_paddr = load_address, // dummy
        .p_filesz = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) + string_len + code_len,
        .p_memsz = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) + string_len + code_len, /* BSSが欲しいならここを増やす */
        .p_flags = PF_R | PF_X,
        .p_align = 0x1000,
    };

    FILE *fp;
    fp = fopen("a.o", "w+b");
    fwrite(&ehdr, sizeof(Elf64_Ehdr), 1, fp);
    fwrite(&phdr, sizeof(Elf64_Phdr), 1, fp);
    fwrite(str, string_len, 1, fp);
    fwrite(code, code_len, 1, fp);
    fclose(fp);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("invalid the number of argument\n");
        return 1;
    }

    code_kind res;

    res = x86_assemble(RS_64, CD_MOV, x86_oprand_from_reg(REG_RAX), x86_oprand_from_imm(1));
    add_codes(res.code, res.len);
    free(res.code);

    res = x86_assemble(RS_64, CD_MOV, x86_oprand_from_reg(REG_RDI), x86_oprand_from_imm(1));
    add_codes(res.code, res.len);
    free(res.code);

    res = x86_assemble(RS_64, CD_MOV, x86_oprand_from_reg(REG_RSI), x86_oprand_from_imm(0x400078));
    add_codes(res.code, res.len);
    free(res.code);

    res = x86_assemble(RS_64, CD_MOV, x86_oprand_from_reg(REG_RDX), x86_oprand_from_imm(6));
    add_codes(res.code, res.len);
    free(res.code);

    res = x86_assemble(RS_64, CD_SYSCALL, none, none);
    add_codes(res.code, res.len);
    free(res.code);

    res = x86_assemble(RS_64, CD_MOV, x86_oprand_from_reg(REG_RAX), x86_oprand_from_imm(0x3c));
    add_codes(res.code, res.len);
    free(res.code);

    res = x86_assemble(RS_64, CD_SYSCALL, none, none);
    add_codes(res.code, res.len);
    free(res.code);

    out_elf64();

    return 0;
}