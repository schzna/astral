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
    assert(b.len == 2 && "test_inst_adc");
    fprintf(stderr, "%x %x\n", b.pointer[0], b.pointer[1]);
    assert(b.pointer[0] == 0x11 && b.pointer[1] == 0xd8 && "test_inst_adc");
    free(b.pointer);

    b = x86_assemble(x32, opcode_adc, x86_make_operands_two(x86_make_operand_reg(eax), x86_make_operand_reg(ebx)));
    assert(b.len == 2 && "test_inst_adc");
    assert(b.pointer[0] == 0x11 && b.pointer[1] == 0xd8 && "test_inst_adc");
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