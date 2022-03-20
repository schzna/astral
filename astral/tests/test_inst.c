#include "testutil.h"
#include <include/x86.h>
#include <string.h>

void test_inst_aaa()
{
    bytes b = x86_assemble(x86, opcode_aaa, x86_make_operands_no());
    assert_code("test_inst_aaa", b, 0x37);
    free(b.pointer);
}

void test_inst_aad()
{
    bytes b = x86_assemble(x86, opcode_aad, x86_make_operands_no());
    assert_code("test_inst_aad", b, 0xd5, 0x0a);
    free(b.pointer);

    b = x86_assemble(x86, opcode_aad, x86_make_operands_one(x86_make_operand_imm(b8, 0x02)));
    assert_code("test_inst_aad", b, 0xd5, 0x02);
    free(b.pointer);
}

void test_inst_aam()
{
    bytes b = x86_assemble(x86, opcode_aam, x86_make_operands_no());
    assert_code("test_inst_aam", b, 0xd4, 0x0a);
    free(b.pointer);

    b = x86_assemble(x86, opcode_aam, x86_make_operands_one(x86_make_operand_imm(b8, 0x14)));
    assert_code("test_inst_aam", b, 0xd4, 0x14);
    free(b.pointer);
}

void test_inst_aas()
{
    bytes b = x86_assemble(x86, opcode_aas, x86_make_operands_no());
    assert_code("test_inst_aas", b, 0x3f);
    free(b.pointer);
}

void test_inst_adc()
{
    bytes b = x86_assemble(x86, opcode_adc, x86_make_operands_two(x86_make_operand_reg(eax), x86_make_operand_reg(ebx)));
    assert_code("test_inst_adc r/m32, r32", b, 0x11, 0xd8);
    free(b.pointer);

    b = x86_assemble(x86, opcode_adc, x86_make_operands_two(x86_make_operand_reg(al), x86_make_operand_imm(b8, 12)));
    assert_code("test_inst_adc al, imm8", b, 0x14, 0x0c);
    free(b.pointer);

    b = x86_assemble(x86, opcode_adc, x86_make_operands_two(x86_make_operand_reg(ax), x86_make_operand_imm(b16, 0x345)));
    assert_code("test_inst_adc ax, imm16", b, 0x66, 0x15, 0x45, 0x03);
    free(b.pointer);

    b = x86_assemble(x86, opcode_adc, x86_make_operands_two(x86_make_operand_reg(eax), x86_make_operand_imm(b32, 0x12345678)));
    assert_code("test_inst_adc eax, imm32", b, 0x15, 0x78, 0x56, 0x34, 0x12);
    free(b.pointer);

    b = x86_assemble(x86, opcode_adc, x86_make_operands_two(x86_make_operand_reg(bl), x86_make_operand_imm(b8, 0x12)));
    assert_code("test_inst_adc r/m8, imm8", b, 0x80, 0xd3, 0x12);
    free(b.pointer);

    b = x86_assemble(x86, opcode_adc, x86_make_operands_two(x86_make_operand_reg(cx), x86_make_operand_imm(b16, 0x1324)));
    assert_code("test_inst_adc r/m16, imm16", b, 0x66, 0x81, 0xd1, 0x24, 0x13);
    free(b.pointer);

    b = x86_assemble(x86, opcode_adc, x86_make_operands_two(x86_make_operand_reg(ecx), x86_make_operand_imm(b32, 0x1324)));
    assert_code("test_inst_adc r/m32, imm32", b, 0x81, 0xd1, 0x24, 0x13, 0x00, 0x00);
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