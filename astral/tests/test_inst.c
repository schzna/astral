#include <assert.h>
#include <include/x86.h>
#include <stdio.h>
#include <string.h>

void test_inst_aaa()
{
    bytes b = x86_assemble(x32, opcode_aaa, x86_make_operands_no());
    assert(b.len == 1 && "test_inst_aaa");
    assert(b.pointer[0] == 0x37 && "test_inst_aaa");
    free(b.pointer);
}

void test_inst_aad()
{
    bytes b = x86_assemble(x32, opcode_aad, x86_make_operands_no());
    assert(b.len == 2 && "test_inst_aad");
    assert(b.pointer[0] == 0xd5 && "test_inst_aad");
    assert(b.pointer[1] == 0x0a && "test_inst_aad");
    free(b.pointer);

    b = x86_assemble(x32, opcode_aad, x86_make_operands_one(x86_make_operand_imm(b8, 0x02)));
    assert(b.len == 2 && "test_inst_aad");
    assert(b.pointer[0] == 0xd5 && "test_inst_aad");
    assert(b.pointer[1] == 0x02 && "test_inst_aad");
    free(b.pointer);
}

void test_inst_aam()
{
    bytes b = x86_assemble(x32, opcode_aam, x86_make_operands_no());
    assert(b.len == 2 && "test_inst_aam");
    assert(b.pointer[0] == 0xd4 && "test_inst_aam");
    assert(b.pointer[1] == 0x0a && "test_inst_aam");
    free(b.pointer);

    b = x86_assemble(x32, opcode_aam, x86_make_operands_one(x86_make_operand_imm(b8, 0x14)));
    assert(b.len == 2 && "test_inst_aam");
    assert(b.pointer[0] == 0xd4 && "test_inst_aam");
    assert(b.pointer[1] == 0x14 && "test_inst_aam");
    free(b.pointer);
}

void test_inst_aas()
{
    bytes b = x86_assemble(x32, opcode_aas, x86_make_operands_no());
    assert(b.len == 1 && "test_inst_aas");
    assert(b.pointer[0] == 0xd4 && "test_inst_aas");
    free(b.pointer);
}

void test_inst_adc()
{
    bytes b = x86_assemble(x32, opcode_adc, x86_make_operands_two(x86_make_operand_reg(eax), x86_make_operand_reg(ebx)));
    fprintf(stderr, "%x %x\n", b.pointer[0], b.pointer[1]);
    assert(b.len == 2 && "test_inst_adc");
    assert(b.pointer[0] == 0x11 && b.pointer[1] == 0xd8 && "test_inst_adc");
    free(b.pointer);

    b = x86_assemble(x32, opcode_adc, x86_make_operands_two(x86_make_operand_reg(al), x86_make_operand_imm(b8, 12)));
    fprintf(stderr, "%x %x\n", b.pointer[0], b.pointer[1]);
    assert(b.len == 2 && "test_inst_adc");
    assert(b.pointer[0] == 0x14 && b.pointer[1] == 0x0c && "test_inst_adc");
    free(b.pointer);

    b = x86_assemble(x32, opcode_adc, x86_make_operands_two(x86_make_operand_reg(ax), x86_make_operand_imm(b16, 0x345)));
    fprintf(stderr, "%x %x %x %x\n", b.pointer[0], b.pointer[1], b.pointer[2], b.pointer[3]);
    assert(b.len == 4 && "test_inst_adc");
    assert(b.pointer[0] == 0x66 && b.pointer[1] == 0x15 && b.pointer[2] == 0x45 && b.pointer[3] == 0x03 && "test_inst_adc");
    free(b.pointer);

    b = x86_assemble(x32, opcode_adc, x86_make_operands_two(x86_make_operand_reg(eax), x86_make_operand_imm(b32, 0x12345678)));
    fprintf(stderr, "%x %x %x %x %x \n", b.pointer[0], b.pointer[1], b.pointer[2], b.pointer[3], b.pointer[4]);
    assert(b.len == 5 && "test_inst_adc");
    assert(b.pointer[0] == 0x15 && b.pointer[1] == 0x78 && b.pointer[2] == 0x56 && b.pointer[3] == 0x34 && b.pointer[4] == 0x12 && "test_inst_adc");
    free(b.pointer);

    b = x86_assemble(x32, opcode_adc, x86_make_operands_two(x86_make_operand_reg(bl), x86_make_operand_imm(b8, 0x12)));
    fprintf(stderr, "%x %x %x\n", b.pointer[0], b.pointer[1], b.pointer[2]);
    assert(b.len == 3 && "test_inst_adc");
    assert(b.pointer[0] == 0x80 && b.pointer[1] == 0xd3 && b.pointer[2] == 0x12 && "test_inst_adc");
    free(b.pointer);
}

int main()
{
    test_inst_aaa();
    test_inst_aad();
    test_inst_aam();
    test_inst_adc();
    return 0;
}