#ifndef INCLUDED_CODE_H
#define INCLUDED_CODE_H
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct
{
    const char *msg;
} error_info;

typedef struct
{
    bool initialized;
    error_info *info;
    size_t capacity, size;
} error_bundle;

error_bundle init_error_bundle()
{
    error_bundle res;
    res.initialized = true;
    res.capacity = 10;
    res.size = 0;
    res.info = (error_info *)calloc(sizeof(error_info), res.capacity);
    return res;
}

void push_error(error_bundle dest, error_info eri)
{
    if (!dest.initialized)
    {
        init_error_bundle(dest);
    }
    if (dest.size >= dest.capacity)
    {
        dest.capacity += 5;
        dest.info = (error_info *)realloc(dest.info, sizeof(error_info) * dest.capacity);
    }
    dest.info[dest.size++] = eri;
}

void error_msg(error_bundle dest, const char *msg)
{
    error_info eri;
    eri.msg = msg;

    push_error(dest, eri);
}

void print_error(error_bundle errors)
{
    for (size_t i = 0; i < errors.size; i++)
    {
        printf("%50s\n", errors.info[i].msg);
    }
}

error_bundle global_error = {
    .initialized = false};

#endif