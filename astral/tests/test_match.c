#include <assert.h>
#include <include/x86.h>

int main()
{
    assert(x86_match_oprands(x86fmt_no, x86_make_operands_no()));
    assert(x86_match_oprand(imm8, x86_make_operand_imm(b8, 0x02)));
    assert(x86_match_oprands(x86fmt_imm8, x86_make_operands_one(
                                              x86_make_operand_imm(b8, 0x02))));
    assert(!x86_match_oprands(x86fmt_no, x86_make_operands_one(
                                             x86_make_operand_imm(b8, 0x02))));
    return 0;
}