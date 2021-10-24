#include "include/astral.h"
#include "include/elf.h"
#include "include/x86.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

void out_elf64(bytes code)
{
    int load_address = 0x400000;
    char *str = "Hello\n";

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
        .p_filesz = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) + string_len + code.len,
        .p_memsz = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) + string_len + code.len, /* BSSが欲しいならここを増やす */
        .p_flags = PF_R | PF_X,
        .p_align = 0x1000,
    };

    FILE *fp;
    fp = fopen("a.o", "w+b");
    fwrite(&ehdr, sizeof(Elf64_Ehdr), 1, fp);
    fwrite(&phdr, sizeof(Elf64_Phdr), 1, fp);
    fwrite(str, string_len, 1, fp);
    fwrite(code.pointer, code.len, 1, fp);
    fclose(fp);
}

int main(int argc, char **argv)
{
    if(argc != 2){
        fprintf(stderr, "astral needs 1 argument.\n");
        fprintf(stderr, "usage: ./astral filename\n");
        return 1;
    }

    //code = "\x48\xc7\xc0\x01\x00\x00\x00\x48\xc7\xc7\x01\x00\x00\x00\x48\xc7\xc6\x78\x00\x40\x00\x48\xc7\xc2\x06\x00\x00\x00\x0f\x05\x48\xc7\xc0\x3c\x00\x00\x00\x0f\x05";

    FILE *fp;
    fp = fopen(argv[1], "rb");
    if(fp == NULL){
        fprintf(stderr, "file%50s not found.\n", argv[1]);
        return 1;
    }

    char cur = 0;
    size_t size_tok, index_toks;
    char *tok;
    bool label, interpreted;
    opecode_type opcode;
    operands oprands;
    bytes code;
    do
    {
        size_tok = 0;
        index_toks = 0;
        interpreted = false;
        do
        {
            cur = fgetc(fp);

            if(cur!=' ' && cur!='\n' && cur != EOF){
                size_tok++;
            }else if(size_tok > 0){
                label = false;
                tok = (char *)calloc(sizeof(char), size_tok + 1);
                if(cur==EOF){
                    fseek(fp, -size_tok, SEEK_END);
                }else{
                    fseek(fp, ftell(fp)-size_tok-1, SEEK_SET);
                }
                for (size_t i = 0; i < size_tok; i++)
                {
                    tok[i] = fgetc(fp);
                    if(i==(size_tok-1)){
                        label = (tok[i] == ':');
                    }
                    if(label)
                        tok[i] = '\0';
                }
                fgetc(fp);
                if(label){
                    //code for label
                }else if(index_toks == 0){
                    interpreted = true;
                    printf("opcode: %s\n", tok);
                    opcode = x86_str2opcode(tok);
                    oprands.num = 0;
                }else if(index_toks == 1){
                    oprands.num = 1;
                    oprands.array[0] = x86_str2oprand(tok);
                }else if(index_toks == 2){
                    oprands.num = 2;
                    oprands.array[1] = x86_str2oprand(tok);
                }
                size_tok = 0;
                index_toks++;
            }
            
        } while ((cur != EOF) && (cur != '\n'));
        if(interpreted){
           code = join_bytes(code, x86_assemble(x32, opcode, oprands));
        }
    } while (cur != EOF);

    fclose(fp);

    out_elf64(code);
    return 0;
}