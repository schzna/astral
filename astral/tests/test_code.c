#include <assert.h>
#include <include/code.h>

int main()
{
    bytes b1 = make_bytes_two(0x12, 0x23);
    bytes b2 = make_bytes_two(0x56, 0x67);
    bytes b = join_bytes(b1, b2);
    assert(b.pointer[0] == 0x12);
    assert(b.pointer[1] == 0x23);
    assert(b.pointer[2] == 0x56);
    assert(b.pointer[3] == 0x67);
    free(b.pointer);
    return 0;
}