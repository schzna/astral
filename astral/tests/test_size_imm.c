#include <assert.h>
#include <include/x86.h>

int main()
{
    assert(b8 == size_imm(120));
    assert(b16 == size_imm(1000));
    assert(b32 == size_imm(40000));
    assert(b64 == size_imm(3147483648));
    return 0;
}