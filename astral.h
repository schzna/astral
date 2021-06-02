#ifndef INCLUDED_ASTRAL_H
#define INCLUDED_ASTRAL_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *code = "";
int len = 0;
int code_index = 0;

void add_code(char byte)
{
    if (len == 0)
    {
        len = 10;
        code = (char *)calloc(sizeof(char), 10);
    }
    else if ((code_index + 1) > len)
    {
        len += 10;
        char *tmp;
        tmp = (char *)realloc((void *)code, sizeof(char) * len);
        code = tmp;
    }
    code[code_index++] = byte;
}

void add_codes(char *bytes, int len_bytes)
{
    if (len == 0)
    {
        len = 10;
        code = (char *)calloc(sizeof(char), 10);
    }
    else if ((code_index + len_bytes) > len)
    {

        len += len_bytes + 10;
        char *tmp;
        tmp = (char *)realloc((void *)code, sizeof(char) * len);
        code = tmp;
    }
    for (size_t i = 0; i < len_bytes; i++)
    {
        code[code_index++] = bytes[i];
    }
}

#endif