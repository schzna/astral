#include <include/error.h>

int main()
{
    error_msg(global_error, "error1");
    error_msg(global_error, "error2");
    print_error(global_error);
    free(global_error.info);
    return 0;
}