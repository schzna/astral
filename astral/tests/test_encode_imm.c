#include <assert.h>
#include <include/x86.h>

int main()
{
    immediate imm;
    imm.size = b8;
    imm.entity.imm64 = 0x0f;
    bytes b = x86_encode_imm(imm, b8);
    assert(b.len == 1);
    assert(b.pointer[0] == 0x0f);
    free(b.pointer);
    return 0;
}