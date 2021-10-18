#include <assert.h>
#include <include/x86.h>

int main()
{
    assert(match_size_imm(120, b8));
    assert(match_size_imm(1000, b16));
    assert(match_size_imm(90000, b32));
    assert(match_size_imm(9147483648, b64));
    return 0;
}