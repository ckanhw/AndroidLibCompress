/* 7z.h -- 7z interface
2010-03-11 : Igor Pavlov : Public domain */

#ifndef __7ZMAIN_H
#define __7ZMAIN_H

#include <pthread.h>
#include <fcntl.h>
#include "7zC/Types.h"

struct MergeData {
    volatile int out_size;
    FILE * fp;
    const char* path;
    int errorno;
    pthread_mutex_t mutex;

    // linker related members
    int is_hook;
    UInt32 text_size;
    UInt32 other_start;
    void* start;
    UInt32 bias;
    UInt32 load_size;
};

#endif
