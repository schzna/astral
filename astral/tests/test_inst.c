#include <assert.h>
#include <include/x86.h>

int main()
{
    operands ops;
    ops.num = 0;
    bytes b = x86_assemble(b32, opcode_aaa, ops);
    assert(b.pointer[0] == 0x37);
    assert(b.len == 1);
    free(b.pointer);

    b = x86_assemble(b64, opcode_aaa, ops);
    assert(b.pointer[0] == 0x37);
    assert(b.len == 1);
    free(b.pointer);
    return 0;
}