#ifndef INCLUDED_TESTUTIL_HEADER
#define INCLUDED_TESTUTIL_HEADER

#include <include/code.h>
#include <stdarg.h>
#include <assert.h>
#include <stdio.h>
#include <stdbool.h>

void assert_code(const char *msg, bytes code, ...){
    va_list ap;
    size_t i = 0;
    va_start(ap, code);
    bool error = false;
    while (i < code.len)
    {
        if(code.pointer[i] != (byte)va_arg(ap, int)){
            error = true;
            break;
        }
        i++;
    }
    if(error){
        fprintf(stderr, msg);
        assert(false);
    }
    va_end(ap);
}

#endif