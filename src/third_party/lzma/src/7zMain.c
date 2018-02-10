/* 7zMain.c - Test application for 7z Decoder
2010-10-28 : Igor Pavlov : Public domain */

#include <jni.h>

#include "../7zC/7z.h"
#include "../7zC/7zAlloc.h"
#include "../7zC/7zCrc.h"
#include "../7zC/7zFile.h"
#include "../7zC/7zVersion.h"

#include "7zMain.h"
#include "hook.h"

#include <android/log.h>
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "lzma", __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "lzma", __VA_ARGS__)

#if 0
#define INFO(...) __android_log_print(ANDROID_LOG_INFO, "lzma", __VA_ARGS__)
#else
#define INFO(...)
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#define SZ_ERROR_FSEEK   100
#define SZ_ERROR_FWRITE  101
#define SZ_ERROR_INVALID 102
#define SZ_ERROR_OPEN    103
#define SZ_ERROR_MALLOC  104
#define SZ_CHMOD_FAIL    105

static ISzAlloc g_Alloc = { SzAlloc, SzFree };

struct MergeData* g_merge = NULL;

// call java method
JavaVM* g_jvm = NULL;
jclass g_szClazz = NULL;

void PrintError(char *sz) {
    LOGE("ERROR: %s", sz);
}

static WRes ChMode(const UInt16 *name, const char* path);

static int Cleanup() {
    INFO("Cleanup");
    if (!g_merge) {
        return SZ_OK;
    }

    if (g_merge->is_hook == 0) {
        pthread_mutex_destroy(&g_merge->mutex);
        if (munmap(g_merge->start, g_merge->load_size) != 0) {
            return SZ_ERROR_INVALID;
        }
    }

    int errorno = g_merge->errorno;
    FILE* fp = g_merge->fp;
    if (!fp || fclose(fp) != 0) {
        return SZ_ERROR_INVALID;
    }
    g_merge->fp = NULL;

    if (errorno != SZ_OK) {
        remove(g_merge->path);
    }
    free(g_merge);
    g_merge = NULL;

    return errorno;
}

static int WriteBack(void* addr, int len, int offset) {
    INFO("WriteBack");
    if (len <= 0 || !g_merge) {
        return SZ_ERROR_INVALID;
    }

    int errorno = SZ_OK;
    pthread_mutex_lock(&(g_merge->mutex));
    do {
        if(fseek(g_merge->fp, offset, SEEK_SET) < 0) {
            errorno = SZ_ERROR_FSEEK;
            break;
        }

        if(fwrite(addr, 1, len, g_merge->fp) <= 0) {
            errorno = SZ_ERROR_FWRITE;
            break;
        }
        break;
    } while(0);
    pthread_mutex_unlock(&(g_merge->mutex));
    return errorno;
}

int writeBackOneoff() {
    INFO("writeBackOneoff");
    if (!g_merge) {
        return SZ_ERROR_INVALID;
    }

    int len = ((g_merge->text_size) & PAGE_MASK);//g_merge->text_size - g_merge->text_size % PAGE_SIZE;
    if(fwrite(g_merge->start, 1, len, g_merge->fp) <= 0) {
        g_merge->errorno = SZ_ERROR_FWRITE;
    }

    if (fwrite((void*)(g_merge->other_start), 1, g_merge->out_size - len, g_merge->fp) <= 0) {
        g_merge->errorno = SZ_ERROR_FWRITE;
    }

    LOGD("write lib to file finish!");
    return Cleanup();
}

int checkException(JNIEnv* env) {
    if ((*env)->ExceptionCheck(env) != 0) {
        LOGE("*** Uncaught exception returned from Java call!\n");
        (*env)->ExceptionDescribe(env);
        return -1;
    }
    return 0;
}

void finishCallback() {
    INFO("finishCallback");
    JNIEnv* env = NULL;
    jint ret = (*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL);
    if (ret != JNI_OK) {
        return;
    }

    jmethodID getInstance = (*env)->GetStaticMethodID(env, g_szClazz, "getInstance", "()Lcom/sam/webkit/sdk/SevenZipUtils;");
    jmethodID finish = (*env)->GetMethodID(env, g_szClazz, "finish", "()V");
    jobject obj = (*env)->CallStaticObjectMethod(env, g_szClazz, getInstance);
    (*env)->CallVoidMethod(env, obj, finish);

    (*env)->DeleteGlobalRef(env, g_szClazz);
    checkException(env);
}

static int Submit(JNIEnv *env, jobject obj) {
    INFO("Submit");
    if (g_merge && g_merge->is_hook > 0) {
        writeBackOneoff();
    }
    return Cleanup();
}

static jint Init(JNIEnv *env, jobject obj, jstring jpath, jstring outFile,
        jint size, jint min, jint max, jint hook) {
    INFO("Init");

    if (g_merge) {
        return SZ_ERROR_INVALID;
    }

    g_merge = (struct MergeData*) malloc(
            sizeof(struct MergeData));
    if (!g_merge || jpath == NULL || outFile == NULL || size <= 0) {
        return 0;
    }

    const char* path = (*env)->GetStringUTFChars(env, jpath, NULL);
    g_merge->errorno = SZ_OK;
    g_merge->out_size = size;
    g_merge->path = (*env)->GetStringUTFChars(env, outFile, NULL);
    g_merge->is_hook = hook;

    if (hook <= 0) {
        pthread_mutex_init(&g_merge->mutex, NULL);
    }

    if( (g_merge->fp = fopen(g_merge->path, "wb")) == NULL) {
        PrintError("open file failed!");
        Cleanup();
        return SZ_ERROR_OPEN;
    }

    if (ChMode(0, g_merge->path)) {
        PrintError("Init chmod failed!");
        Cleanup();
        return SZ_CHMOD_FAIL;
    }

    if (pre_alloc(size, min, max, path) != 0) {
        return SZ_ERROR_INVALID;
    }
    return SZ_OK;
}

static void DecodeAndMerge(JNIEnv * env, jclass thiz,
        jobject assetManager, jstring jinpath, jint joffset, jint jsize, jint szoff) {
    INFO("DecodeAndMerge");
    if(!g_merge || g_merge->errorno != SZ_OK)
        return;

    if (!g_merge || jsize <= 0) {
        g_merge->errorno = SZ_ERROR_INVALID;
        return;
    }

    const char* infilename = NULL;
    if (jinpath != NULL) {
        infilename = (*env)->GetStringUTFChars(env, jinpath, NULL);
    }

    CFileInStream archiveStream;
    CLookToRead lookStream;
    CSzArEx db;
    SRes res;
    ISzAlloc allocImp;
    ISzAlloc allocTempImp;
    UInt16 *temp = NULL;
    size_t tempSize = 0;

    if (assetManager != NULL) {
        archiveStream.file.mgr = AAssetManager_fromJava(env, assetManager);
    } else
        archiveStream.file.mgr = NULL;

    allocImp.Alloc = SzAlloc;
    allocImp.Free = SzFree;

    allocTempImp.Alloc = SzAllocTemp;
    allocTempImp.Free = SzFreeTemp;

    // sam change
    CSzFile* file = &archiveStream.file;
    file->offset = szoff;

    int ress=-1;
    if ((ress = InFile_Open(&archiveStream.file, infilename))) {
        PrintError("can not open input file");
        g_merge->errorno = SZ_ERROR_OPEN;
        return;
    }

    Byte* reladdr = g_merge->start + joffset;

    if (!reladdr) {
        g_merge->errorno = SZ_ERROR_MALLOC;
        return;
    }

    FileInStream_CreateVTable(&archiveStream);
    LookToRead_CreateVTable(&lookStream, False);

    lookStream.realStream = &archiveStream.s;
    LookToRead_Init(&lookStream);

    CrcGenerateTable();

    SzArEx_Init(&db);
    res = SzArEx_Open(&db, &lookStream.s, &allocImp, &allocTempImp);

    if (res == SZ_OK) {
        UInt32 i;

        UInt32 blockIndex = 0xFFFFFFFF;
        Byte *outBuffer = 0;
        size_t outBufferSize = 0;

        for (i = 0; i < db.db.NumFiles; i++) {
            size_t offset = 0;
            size_t outSizeProcessed = 0;
            const CSzFileItem *f = db.db.Files + i;
            size_t len;

            res = SzArEx_Extract(&db, &lookStream.s, i, &blockIndex,
                    &reladdr, // store address
                    &outBufferSize, &offset, &outSizeProcessed, &allocImp,
                    &allocTempImp, 1);

            if (res != SZ_OK) {
                break;
            }

            if (g_merge->is_hook == 0) {
                res = WriteBack(reladdr, outSizeProcessed, joffset);
                if (res != SZ_OK) {
                    break;
                }
            }
        }
        IAlloc_Free(&allocImp, outBuffer);
    }
    SzArEx_Free(&db, &allocImp);
    SzFree(NULL, temp);

    File_Close(&archiveStream.file);
    g_merge->errorno = res;
}

static int Buf_EnsureSize(CBuf *dest, size_t size)
{
    if (dest->size >= size)
        return 1;
    Buf_Free(dest, &g_Alloc);
    return Buf_Create(dest, size, &g_Alloc);
}

static Byte kUtf8Limits[5] = { 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };

static Bool Utf16_To_Utf8(Byte *dest, size_t *destLen, const UInt16 *src, size_t srcLen)
{
    size_t destPos = 0, srcPos = 0;
    for (;;) {
        unsigned numAdds;
        UInt32 value;
        if (srcPos == srcLen) {
            *destLen = destPos;
            return True;
        }
        value = src[srcPos++];
        if (value < 0x80) {
            if (dest)
                dest[destPos] = (char)value;
            destPos++;
            continue;
        }
        if (value >= 0xD800 && value < 0xE000) {
            UInt32 c2;
            if (value >= 0xDC00 || srcPos == srcLen)
                break;
            c2 = src[srcPos++];
            if (c2 < 0xDC00 || c2 >= 0xE000)
                break;
            value = (((value - 0xD800) << 10) | (c2 - 0xDC00)) + 0x10000;
        }
        for (numAdds = 1; numAdds < 5; numAdds++)
            if (value < (((UInt32)1) << (numAdds * 5 + 6)))
                break;
        if (dest)
            dest[destPos] = (char)(kUtf8Limits[numAdds - 1] + (value >> (6 * numAdds)));
        destPos++;
        do {
            numAdds--;
            if (dest)
                dest[destPos] = (char)(0x80 + ((value >> (6 * numAdds)) & 0x3F));
            destPos++;
        } while (numAdds != 0);
    }
    *destLen = destPos;
    return False;
}

static SRes Utf16_To_Utf8Buf(CBuf *dest, const UInt16 *src, size_t srcLen)
{
    size_t destLen = 0;
    Bool res;
    Utf16_To_Utf8(NULL, &destLen, src, srcLen);
    destLen += 1;
    if (!Buf_EnsureSize(dest, destLen))
        return SZ_ERROR_MEM;
    res = Utf16_To_Utf8(dest->data, &destLen, src, srcLen);
    dest->data[destLen] = 0;
    return res ? SZ_OK : SZ_ERROR_FAIL;
}

static SRes Utf16_To_Char(CBuf *buf, const UInt16 *s, int fileMode)
{
    int len = 0;
    for (len = 0; s[len] != '\0'; len++);
    fileMode = fileMode;
    return Utf16_To_Utf8Buf(buf, s, len);
}

static WRes MyCreateDir(const UInt16 *name, const char* path)
{
    CBuf buf;
    WRes res;
    char finalPath[1024] = {0};
    Buf_Init(&buf);
    RINOK(Utf16_To_Char(&buf, name, 1));
    if (path) {
        if (strlen(path) >= sizeof(finalPath))
            PrintError("path too long");
        else
            strcpy(finalPath, path);
    }
    if (strlen(buf.data) >= (sizeof(finalPath) - strlen(finalPath)))
        PrintError("path too long");
    else
        strcat(finalPath, buf.data);
    res = mkdir(finalPath, 0777) == 0 ? 0 : errno;
    Buf_Free(&buf, &g_Alloc);
    return res;
}

// chmod to 0755
static WRes ChMode(const UInt16 *name, const char* path)
{
    CBuf buf;
    WRes res;
    char finalPath[1024] = {0};
    if (name) {
        Buf_Init(&buf);
        RINOK(Utf16_To_Char(&buf, name, 1));
    }
    if (path) {
        if (strlen(path) >= sizeof(finalPath)) {
            PrintError("path too long");
        } else {
            snprintf(finalPath, 1024, "%s", path);
        }
    }
    if (name) {
        if (strlen(buf.data) >= (sizeof(finalPath) - strlen(finalPath))) {
            PrintError("path too long");
        } else {
            strncat(finalPath, buf.data, 1024);
        }
        Buf_Free(&buf, &g_Alloc);
    }
    res = chmod(finalPath, 0755) == 0 ? 0 : errno;
    return res;
}

static WRes OutFile_OpenUtf16(CSzFile *p, const UInt16 *name, const char* path)
{
    CBuf buf;
    WRes res;
    char finalPath[1024] = {0};
    Buf_Init(&buf);
    RINOK(Utf16_To_Char(&buf, name, 1));
    if (path) {
        if (strlen(path) >= sizeof(finalPath))
            PrintError("path too long");
        else
            strcpy(finalPath, path);
    }
    if (strlen(buf.data) >= (sizeof(finalPath) - strlen(finalPath)))
        PrintError("path too long");
    else
        strcat(finalPath, buf.data);
    res = OutFile_Open(p, finalPath);
    Buf_Free(&buf, &g_Alloc);
    return res;
}

static Bool willSkip(int version, const UInt16 *name) {
    Bool res = False;
    CBuf buf;
    Buf_Init(&buf);
    Utf16_To_Char(&buf, name, 1);
    char* pos;
    if (strlen(buf.data) >= 20 && (pos = strstr(buf.data, "libplat_support_")) != NULL) {
        pos += 16;
        switch (version) {
        case 23:
            if (*pos != '6' || *(pos +1) != '0') {
                res = True;
            }
            break;
        case 22:
            if(*pos != '5' || *(pos +1) != '1') {
                res = True;
            }
            break;
        case 21:
            if (*pos != '5' || *(pos +1) != '0') {
                res = True;
            }
            break;
        case 20:
            if (*pos != '4' || *(pos +1) != '4' || *(pos +2) != '3') {
                res = True;
            }
            break;
        case 19:
            if (*pos != '4' || *(pos +1) != '4') {
                res = True;
            }
            break;
        case 18:
            if (*pos != '4' || *(pos +1) != '3') {
                res = True;
            }
            break;
        case 17:
            if (*pos != '4' || *(pos +1) != '2') {
                res = True;
            }
            break;
        case 16:
            if (*pos != '4' || *(pos +1) != '1') {
                res = True;
            }
            break;
        case 14:
        case 15:
            if (*pos != '4' || *(pos +1) != '0') {
                res = True;
            }
            break;
        default:
            break;
        }
    }
    Buf_Free(&buf, &g_Alloc);

    return res;
}

static jint Extract(JNIEnv *env, jobject obj, jstring filePath, jstring outPath,
        jint offset, jint version) {
    CFileInStream archiveStream;
    CLookToRead lookStream;
    CSzArEx db;
    SRes res;
    ISzAlloc allocImp;
    ISzAlloc allocTempImp;
    UInt16 *temp = NULL;
    size_t tempSize = 0;
    allocImp.Alloc = SzAlloc;
    allocImp.Free = SzFree;
    allocTempImp.Alloc = SzAllocTemp;
    allocTempImp.Free = SzFreeTemp;
    const char* cfilePath = NULL;
    const char* coutPath = NULL;

    if (filePath != NULL)
        cfilePath = (*env)->GetStringUTFChars(env, filePath, NULL);
    else {
        PrintError("file path error");
        return 1;
    }

    if (outPath != NULL)
        coutPath = (*env)->GetStringUTFChars(env, outPath, NULL);
    else {
        PrintError("out path error");
        return 1;
    }

    if (InFile_Open(&archiveStream.file, cfilePath)) {
        PrintError("can not open input file");
        return 1;
    }

    FileInStream_CreateVTable(&archiveStream);
    LookToRead_CreateVTable(&lookStream, False);
    lookStream.realStream = &archiveStream.s;
    LookToRead_Init(&lookStream);
    CrcGenerateTable();

    // add offset
    CSzFile* file = &archiveStream.file;
    file->offset = offset;

    SzArEx_Init(&db);
    res = SzArEx_Open(&db, &lookStream.s, &allocImp, &allocTempImp);

    if (res == SZ_OK) {
        UInt32 i;
        UInt32 blockIndex = 0xFFFFFFFF;
        Byte *outBuffer = 0;
        size_t outBufferSize = 0;

        for (i = 0; i < db.db.NumFiles; i++) {
            size_t offset = 0;
            size_t outSizeProcessed = 0;
            const CSzFileItem *f = db.db.Files + i;
            size_t len;
            len = SzArEx_GetFileNameUtf16(&db, i, NULL);

            if (len > tempSize) {
                SzFree(NULL, temp);
                tempSize = len;
                temp = (UInt16 *)SzAlloc(NULL, tempSize * sizeof(temp[0]));
                if (temp == 0) {
                    res = SZ_ERROR_MEM;
                    break;
                }
            }

            SzArEx_GetFileNameUtf16(&db, i, temp);

            // skip extracting unmatched files
            if (willSkip(version, temp)) {
                continue;
            }

            if (!f->IsDir) {
                res = SzArEx_Extract(&db, &lookStream.s, i,
                    &blockIndex, &outBuffer, &outBufferSize,
                    &offset, &outSizeProcessed,
                    &allocImp, &allocTempImp, 0);
                if (res != SZ_OK)
                    break;
            }

            CSzFile outFile;
            size_t processedSize;
            size_t j;
            UInt16 *name = (UInt16 *)temp;
            const UInt16 *destPath = (const UInt16 *)name;

            for (j = 0; name[j] != 0; j++)
                if (name[j] == '/') {
                    name[j] = 0;
                    MyCreateDir(name, coutPath);
                    name[j] = CHAR_PATH_SEPARATOR;
                }

            if (f->IsDir) {
                MyCreateDir(destPath, coutPath);
                continue;
            }
            else if (OutFile_OpenUtf16(&outFile, destPath, coutPath)) {
                PrintError("can not open output file");
                res = SZ_ERROR_FAIL;
                break;
            }

            processedSize = outSizeProcessed;
            if (File_Write(&outFile, outBuffer + offset, &processedSize) != 0 || processedSize != outSizeProcessed) {
                PrintError("can not write output file");
                res = SZ_ERROR_FAIL;
                break;
            }

            if (File_Close(&outFile)) {
                PrintError("can not close output file");
                res = SZ_ERROR_FAIL;
                break;
            }
            if (ChMode(destPath, coutPath)) {
                PrintError("chmod failed!");
                res = SZ_CHMOD_FAIL;
                break;
            }
        }
        IAlloc_Free(&allocImp, outBuffer);
    }
    SzArEx_Free(&db, &allocImp);
    SzFree(NULL, temp);
    File_Close(&archiveStream.file);

    if (res == SZ_OK)
        return 0;
    if (res == SZ_ERROR_UNSUPPORTED)
        PrintError("decoder doesn't support this archive");
    else if (res == SZ_ERROR_MEM)
        PrintError("can not allocate memory");
    else if (res == SZ_ERROR_CRC)
        PrintError("CRC error");

    LOGE("Extract error: %d", res);
    return 1;
}

static int DoHook(JNIEnv * env, jclass thiz, jint version, jboolean flag) {
    int res = so_entry(version, flag);
    return res;
}

static int SymLink(JNIEnv * env, jclass thiz, jstring jsrc, jstring jdest) {
    const char* csrc = NULL;
    const char* cdest = NULL;
    int res = -1;
    if (jsrc == NULL || jdest == NULL) {
        return res;
    }

    csrc = (*env)->GetStringUTFChars(env, jsrc, NULL);
    cdest = (*env)->GetStringUTFChars(env, jdest, NULL);

    if (csrc != NULL && cdest != NULL) {
        res = symlink(csrc, cdest);
    }

    if (csrc != NULL)  {
        (*env)->ReleaseStringUTFChars(env, jsrc, csrc);
    }
    if (cdest != NULL)  {
        (*env)->ReleaseStringUTFChars(env, jdest, cdest);
    }
    return res;
}

static void HookDlsym(JNIEnv * env, jclass thiz) {
    hook_dlsym();
}

static int CheckNativeMethods(JNIEnv * env, jclass thiz, jstring libPath, jboolean hookEnabled) {
    return check_native_methods(env, thiz, libPath, hookEnabled);
}

static JNINativeMethod gJavaMethods[] = {
        { "init", "(Ljava/lang/String;Ljava/lang/String;IIII)I",
                (void*) Init },
        { "submit", "()I",
                (void*) Submit },
        { "decodeAndMerge", "(Landroid/content/res/AssetManager;Ljava/lang/String;III)V",
                (void*) DecodeAndMerge },
        { "extract", "(Ljava/lang/String;Ljava/lang/String;II)I",
                (void*) Extract },
        { "doHook", "(IZ)I",
                (void*) DoHook },
        { "hookDlsym", "()V",
                (void*) HookDlsym },
        { "nativeCheckNativeMethods", "(Ljava/lang/String;Z)I",
                (void*) CheckNativeMethods },
};

static JNINativeMethod gFileUtilsJavaMethods[] = {
        { "nativeSymlink", "(Ljava/lang/String;Ljava/lang/String;)I",
                (void*) SymLink },
};

static int registerNativeMethods(JNIEnv* env, const char* className,
        JNINativeMethod* gMethods, int numMethods) {
    jclass clazz;
    clazz = (*env)->FindClass(env, className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if ((*env)->RegisterNatives(env, clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }

    if (g_szClazz == NULL) {
        g_szClazz = (*env)->NewGlobalRef(env, clazz);
    }
    return JNI_TRUE;
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env = NULL;
    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_4) != JNI_OK) {
        return 0;
    }

    int ret = JNI_FALSE;
    ret = registerNativeMethods(env, "com/sam/webkit/sdk/SevenZipUtils",
            gJavaMethods, sizeof(gJavaMethods) / sizeof(gJavaMethods[0]));

    if (ret == JNI_FALSE) {
        return -1;
    }
    ret = registerNativeMethods(env, "com/sam/webkit/sdk/FileUtils",
            gFileUtilsJavaMethods, sizeof(gFileUtilsJavaMethods) / sizeof(gFileUtilsJavaMethods[0]));
    if (ret == JNI_FALSE) {
        return -1;
    }

    g_jvm = vm;
    return JNI_VERSION_1_4;
}
