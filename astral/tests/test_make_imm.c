#include <assert.h>
#include <include/x86.h>

int main()
{
    operand oprand = x86_make_operand_imm(b8, 0x02);
    assert(oprand.type == oprand_imm);
    assert(oprand.entity.imm.size == b8);
    assert(oprand.entity.imm.entity.imm8 == 0x02);
    return 0;
}