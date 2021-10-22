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
    byte tmp=0;
    while (i < code.len)
    {
        tmp = (byte)va_arg(ap, int);
        if(code.pointer[i] != tmp){
            error = true;
            break;
        }
        i++;
    }
    if(error){
        fprintf(stderr, msg);
        fprintf(stderr, "\n");
        for (size_t j = 0; j < code.len; j++)
        {
            fprintf(stderr, "0x%x ", code.pointer[j]);
        }
        fprintf(stderr, "\n");
        for (size_t j = 0; j < code.len; j++)
        {
            if(j==i){
                fprintf(stderr, "^0x%x", tmp);
            }else{
                fprintf(stderr, "     ");
            }
        }
        fprintf(stderr, "\n");
        assert(false);
    }
    va_end(ap);
}

#endif