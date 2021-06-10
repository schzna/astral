#include <assert.h>
#include <include/x86.h>

int main()
{
    bytes b = x86_assemble(b32, opcode_add, x86_make_operands_two(x86_make_operand_reg32(eax), x86_make_operand_imm(b32, 0x12345678)));
    assert(b.len == 5);
    assert(b.pointer[0] == 0x05);
    assert(b.pointer[1] == 0x12);
    assert(b.pointer[2] == 0x34);
    assert(b.pointer[3] == 0x56);
    assert(b.pointer[4] == 0x78);
    free(b.pointer);
    return 0;
}