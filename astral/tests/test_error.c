#include <assert.h>
#include <include/error.h>
#include <string.h>

int main()
{
    error_msg(global_error, "error1");
    assert(global_error->size == 1);
    assert(global_error->capacity >= 1);
    error_msg(global_error, "error2");
    assert(global_error->size == 2);
    assert(global_error->capacity >= 2);
    assert(strcmp(global_error->info[0].msg, "error1") == 0);
    assert(strcmp(global_error->info[1].msg, "error2") == 0);
    clear_error(global_error);
    error_msg(global_error, "error1");
    assert(strcmp(global_error->info[0].msg, "error1") == 0);
    print_error(global_error);
    free(global_error->info);
    return 0;
}