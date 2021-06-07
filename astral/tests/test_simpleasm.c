#include <assert.h>
#include <include/x86.h>

int main()
{
    operands ops;
    ops.num = 2;
    ops.array[0].type = oprand_reg;
    ops.array[0].entity.reg.size = b32;
    ops.array[0].entity.reg.entity.r32 = eax;
    ops.array[1].type = oprand_imm;
    ops.array[1].entity.imm.imm32 = 0x12345678;
    bytes b = x86_assemble(b32, opcode_add, ops);
    assert(b.len == 5);
    assert(b.pointer[0] == 0x05);
    assert(b.pointer[1] == 0x12);
    assert(b.pointer[2] == 0x34);
    assert(b.pointer[3] == 0x56);
    assert(b.pointer[4] == 0x78);
    return 0;
}