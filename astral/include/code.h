#ifndef INCLUDED_CODE_H
#define INCLUDED_CODE_H

#include <stdlib.h>
#include <string.h>

typedef unsigned char byte;

typedef struct
{
    byte *pointer;
    size_t len;
} bytes;

bytes make_bytes(byte *p, size_t l)
{
    bytes res;
    res.pointer = p;
    res.len = l;
    return res;
}

bytes make_bytes_one(byte b)
{
    bytes res;
    res.pointer = (byte *)calloc(sizeof(byte), 1);
    res.pointer[0] = b;
    res.len = 1;
    return res;
}

bytes make_bytes_two(byte b1, byte b2)
{
    bytes res;
    res.pointer = (byte *)calloc(sizeof(byte), 1);
    res.pointer[0] = b1;
    res.pointer[1] = b2;
    res.len = 2;
    return res;
}

bytes make_bytes_three(byte b1, byte b2, byte b3)
{
    bytes res;
    res.pointer = (byte *)calloc(sizeof(byte), 1);
    res.pointer[0] = b1;
    res.pointer[1] = b2;
    res.pointer[2] = b3;
    res.len = 3;
    return res;
}

bytes join_bytes(bytes b1, bytes b2)
{
    if(b1.len==0)
        return b2;
    if(b2.len==0)
        return b1;
    bytes res;
    res.len = b1.len + b2.len;
    res.pointer = (byte *)calloc(sizeof(byte), res.len);
    memcpy(res.pointer, b1.pointer, b1.len);
    memcpy(res.pointer + b1.len, b2.pointer, b2.len);
    free(b1.pointer);
    free(b2.pointer);
    return res;
}

#endif