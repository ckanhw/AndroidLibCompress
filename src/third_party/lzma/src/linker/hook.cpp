/* Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <jni.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <malloc.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>

#include "linker.h"

#include <android/log.h>
#define  LOG_TAG    "testhook"
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG,__VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,__VA_ARGS__)

#define  LOGD(...)  //__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG,__VA_ARGS__)

#undef PAGE_START
#define PAGE_START(addr, size) ~((size) - 1) & (addr)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t flags;
    void*   reserved_addr;
    size_t  reserved_size;
    int     relro_fd;
    int     library_fd;
} android_dlextinfo;

const int JniMethosCount = 9;
const char* JniMethods[] = {
        // TODO
        };

uint32_t get_module_base(pid_t pid, const char *module_path) {
    FILE *fp = NULL;
    char *pch = NULL;
    char filename[32];
    char line[512];
    uint32_t addr = 0;

    if (pid < 0) {
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    if ((fp = fopen(filename, "r")) == NULL) {
        LOGE("open %s failed!", filename);
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module_path)) {
            pch = strtok(line, "-");
            if (strlen(pch) <= 8) {  // cpu 32
                addr = strtoul(pch, NULL, 16);
            } else {
                LOGE("64bit address %s", pch);
            }
            break;
        }
    }

    fclose(fp);
    return addr;
}

uint32_t find_got_entry_address(const char *module_path, const char *symbol_name) {
    uint32_t module_base = get_module_base(-1, module_path);

    if (module_base == 0) {
        LOGE("[-] it seems that process %d does not dependent on %s", getpid(), module_path);
        return 0;
    }

    LOGD("[+] base address of %s: 0x%x", module_path, module_base);

    int fd = open(module_path, O_RDONLY);
    if (fd == -1) {
        LOGE("[-] open %s error!", module_path);
        return 0;
    }

    Elf32_Ehdr *elf_header = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));

    int sizet = read(fd, elf_header, sizeof(Elf32_Ehdr));
    if ( sizet != sizeof(Elf32_Ehdr)) {

        LOGE("[-] read %s error! in %s at line %d, size:%d, expect:%d, fd:%d, errorno: %d, addr:%p",
                module_path, __FILE__, __LINE__
                , sizet, sizeof(Elf32_Ehdr), fd, errno, elf_header
            );
        return 0;
    }

    uint32_t sh_base = elf_header->e_shoff;
    uint32_t ndx = elf_header->e_shstrndx;
    uint32_t shstr_base = sh_base + ndx * sizeof(Elf32_Shdr);
    LOGD("[+] start of section headers: 0x%x", sh_base);
    LOGD("[+] section header string table index: %d", ndx);
    LOGD("[+] section header string table offset: 0x%x", shstr_base);

    lseek(fd, shstr_base, SEEK_SET);
    Elf32_Shdr *shstr_shdr = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr));
    if (read(fd, shstr_shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr)) {
        LOGE("[-] read %s error! in %s at line %d", module_path, __FILE__, __LINE__);
        return 0;
    }
    LOGD("[+] section header string table offset: 0x%x", shstr_shdr->sh_offset);

    char *shstrtab = (char *)malloc(sizeof(char) * shstr_shdr->sh_size);
    lseek(fd, shstr_shdr->sh_offset, SEEK_SET);
    if (read(fd, shstrtab, shstr_shdr->sh_size) != shstr_shdr->sh_size) {
        LOGE("[-] read %s error! in %s at line %d", module_path, __FILE__, __LINE__);
        return 0;
    }

    Elf32_Shdr *shdr = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr));
    Elf32_Shdr *relplt_shdr = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr));
    Elf32_Shdr *dynsym_shdr = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr));
    Elf32_Shdr *dynstr_shdr = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr));

    lseek(fd, sh_base, SEEK_SET);
    if (read(fd, shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr)) {
        LOGE("[-] read %s error! in %s at line %d", module_path, __FILE__, __LINE__);
        perror("Error");
        return 0;
    }
    int i = 1;
    char *s = NULL;
    for (; i < elf_header->e_shnum; i++) {
        s = shstrtab + shdr->sh_name;
        if (strcmp(s, ".rel.plt") == 0) {
            memcpy(relplt_shdr, shdr, sizeof(Elf32_Shdr));
        }
        else if (strcmp(s, ".dynsym") == 0) {
            memcpy(dynsym_shdr, shdr, sizeof(Elf32_Shdr));
        }
        else if (strcmp(s, ".dynstr") == 0) {
            memcpy(dynstr_shdr, shdr, sizeof(Elf32_Shdr));
        }

        if (read(fd, shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr)) {
            LOGD("[-] read %s error! i = %d, in %s at line %d", module_path, i, __FILE__, __LINE__);
            return 0;
        }
    }

    LOGD("[+] offset of .rel.plt section: 0x%x", relplt_shdr->sh_offset);

    // read dynmaic symbol string table
    char *dynstr = (char *)malloc(sizeof(char) * dynstr_shdr->sh_size);
    lseek(fd, dynstr_shdr->sh_offset, SEEK_SET);
    if (read(fd, dynstr, dynstr_shdr->sh_size) != dynstr_shdr->sh_size) {
        LOGD("[-] read %s error!", module_path);
        return 0;
    }

    // read dynamic symbol table
    Elf32_Sym *dynsymtab = (Elf32_Sym *)malloc(dynsym_shdr->sh_size);
    lseek(fd, dynsym_shdr->sh_offset, SEEK_SET);
    if (read(fd, dynsymtab, dynsym_shdr->sh_size) != dynsym_shdr->sh_size) {
        LOGD("[-] read %s error!", module_path);
        return 0;
    }

    // read each entry of relocation table
    Elf32_Rel *rel_ent = (Elf32_Rel *)malloc(sizeof(Elf32_Rel));
    lseek(fd, relplt_shdr->sh_offset, SEEK_SET);
    if (read(fd, rel_ent, sizeof(Elf32_Rel)) != sizeof(Elf32_Rel)) {
        LOGD("[-] read %s error!", module_path);
        return 0;
    }

    uint32_t offset ;//= rel_ent->r_offset;
    for (i = 0; i < relplt_shdr->sh_size / sizeof(Elf32_Rel); i++) {

        ndx = ELF32_R_SYM(rel_ent->r_info);

        if (strcmp(dynstr + dynsymtab[ndx].st_name, symbol_name) == 0) {
            LOGD("[+] got entry offset of %s: 0x%x", symbol_name, rel_ent->r_offset);
            offset = rel_ent->r_offset;
            break;
        }
        if (read(fd, rel_ent, sizeof(Elf32_Rel)) != sizeof(Elf32_Rel)) {
            LOGD("[-] read %s error!", module_path);
            return 0;
        }
    }


  //  uint32_t offset = rel_ent->r_offset;
    Elf32_Half type = elf_header->e_type; // ET_EXEC or ET_DYN

    free(elf_header);
    free(shstr_shdr);
    free(shstrtab);
    free(shdr);
    free(relplt_shdr);
    free(dynsym_shdr);
    free(dynstr_shdr);
    free(dynstr);
    free(dynsymtab);
    free(rel_ent);

    if (type == ET_EXEC) {
        return offset ;
    }
    else if (type == ET_DYN) {
        return offset + module_base;
    }

    return 0;
}

uint32_t do_hook(const char *module_path, uint32_t hook_func, const char *symbol_name) {
    uint32_t entry_addr = find_got_entry_address(module_path, symbol_name);

    if (entry_addr == 0) {
        LOGE("find got entry address failed!");
        return 0;
    }

    uint32_t original_addr = 0;

    memcpy(&original_addr, (uint32_t *)entry_addr, sizeof(uint32_t));

    uint32_t page_size = getpagesize();
    uint32_t entry_page_start = PAGE_START(entry_addr, page_size);

    int res = mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
    if (res != 0) {
        LOGE("hook failed! ");
        return 0;
    }

    memcpy((uint32_t *)entry_addr, &hook_func, sizeof(uint32_t));
    return original_addr;
}

typedef void* (*TYPE1)(const char *pathname, int mode);
typedef void* (*TYPE2)(void* handler, const char* symbol);
typedef void* (*TYPE4)(const char* filename, int flags, const android_dlextinfo* extinfo);

void* (*g_dlopen)(const char *pathname, int mode);
void* (*g_dlsym)(void* handler, const char* symbol);
void* (*g_dlopen_ext)(const char* filename, int flags, const android_dlextinfo* extinfo);

soinfo* blink_soinfo = nullptr;
int g_enable_hook = 0;

void* h_dlsym(void* handler, const char* symbol) {
    if (g_enable_hook < 0) {
        return g_dlsym(handler, symbol);
    }

    if (blink_soinfo != nullptr && handler  == blink_soinfo) {
        LOGD("dlsym symbol %s", symbol);
        soinfo* found = nullptr;
        return dlsym_handle_lookup(reinterpret_cast<soinfo*>(handler), &found, symbol);
    }

    return g_dlsym(handler, symbol);
}

extern void writeBackOneoff();
extern void finishCallback();

void* h_dlopen(const char *pathname, int mode) {
    if (g_enable_hook < 0) {
        return (*g_dlopen)(pathname, mode);
    }

    if (strstr(pathname, "libname") == NULL) {
        return (*g_dlopen)(pathname, mode);
    }

    if (blink_soinfo != nullptr) {
        return blink_soinfo;
    }
    LOGD("dlopen library : %s", pathname);
    blink_soinfo = do_dlopen(pathname, mode);

    if (!blink_soinfo) {
        LOGD("do_dlopen return null");
        writeBackOneoff();
        return (*g_dlopen)(pathname, mode);
    }
    finishCallback();
    return blink_soinfo;
}

void* h_dlopen_ext(const char* filename, int flags, const android_dlextinfo* extinfo) {
    if (g_enable_hook < 0) {
        return (*g_dlopen_ext)(filename, flags, extinfo);
    }

    if (strstr(filename, "libname") == NULL) {
        return (*g_dlopen_ext)(filename, flags, extinfo);
    }

    LOGD("h_dlopen_ext");
    return h_dlopen(filename, flags);
}

void* h_dlsym1(void* handler, const char* symbol) {
    void* value = g_dlsym(handler, symbol);
    if (!value && sizeof(void*) < 8) {
        soinfo* so = (soinfo*) handler;
        if (strstr(so->name, "libname") != NULL) {
            LOGE("%s not found, error:%s, libname:%s", symbol, dlerror(), so->name);
        }
    }

    return value;
}

void hook_dlsym() {
    // only for dalvik
    const char* LIB_DVM = "/system/lib/libdvm.so";
    g_dlsym = (TYPE2)do_hook(LIB_DVM, (uint32_t)h_dlsym1, "dlsym");

    if (!g_dlsym) {
        LOGE("hook dlsym failed");
    }
}

int check_native_methods(JNIEnv * env, jclass thiz, jstring libPath, jboolean hookEnabled) {
    const char* cstr = NULL;
    char msg[255];
    int res = 0;
    void* handler = nullptr;

    if (libPath == NULL || env == NULL) {
        goto bailout;
    }

    cstr = env->GetStringUTFChars(libPath, NULL);
    if (cstr == NULL) {
        goto bailout;
    }
    if (hookEnabled) {
        handler = blink_soinfo;
    } else {
        handler = dlopen(cstr, RTLD_LAZY);
    }

    if (!handler) {
        res = -1;
        snprintf(msg, 255, "CheckNativeMethods dlopen:%s, %s", cstr, dlerror());
        goto bailout;
    }

    for (int i = 0; i < JniMethosCount; ++i) {
        bool addr = false;
        if (hookEnabled) {
            addr = h_dlsym(handler, JniMethods[i]);
        } else {
            addr = dlsym(handler, JniMethods[i]);
        }
        if (!addr) {
            res = -1;
            snprintf(msg, 255, "CheckNativeMethods dlsym:%s, %s", JniMethods[i], dlerror());
            goto bailout;
        }
    }
bailout:
    if (cstr) {
        env->ReleaseStringUTFChars(libPath, cstr);
    }

    if (res < 0) {
        LOGE(msg);
        jclass cls = env->FindClass("java/lang/RuntimeException");
        if (cls != NULL) {
            env->ThrowNew(cls, msg);
        }
    } else {
        LOGI("check_native_methods PASS");
    }

    return res;
}

int so_entry(int version, jboolean flag) {
    const char* LIB_C = "/system/lib/libc.so";
    const char* LIB_ART = "/system/lib/libart.so";
    const char* LIB_DVM = "/system/lib/libdvm.so";
    const char* LIB_NATIVE_LOADER = "/system/lib/libnativeloader.so";

    unsigned res = 0;

    // temporally, API Level above 21 not supported.
    if (!flag || version >= 21) {
        g_enable_hook = -1;
        return res;
    }

    if (version >= 24) { // Android N
        g_dlsym = (TYPE2)do_hook(LIB_ART, (uint32_t)h_dlsym, "dlsym");
        g_dlopen_ext = (TYPE4)do_hook(LIB_NATIVE_LOADER, (uint32_t)h_dlopen_ext, "android_dlopen_ext");
        res = g_dlsym && g_dlopen_ext;
    } else if (version >= 21) { // Android L
        g_dlopen = (TYPE1)do_hook(LIB_ART, (uint32_t)h_dlopen, "dlopen");
        g_dlsym = (TYPE2)do_hook(LIB_ART, (uint32_t)h_dlsym, "dlsym");
        res = g_dlopen && g_dlsym;
    } else { // below Android L
        g_dlopen = (TYPE1)do_hook(LIB_DVM, (uint32_t)h_dlopen, "dlopen");
        g_dlsym = (TYPE2)do_hook(LIB_DVM, (uint32_t)h_dlsym, "dlsym");
        res = g_dlopen && g_dlsym;
    }

    if (!res) {
        LOGE("hook failed!");
    }
    return res;
}

int pre_alloc(size_t size, uint32_t min, uint32_t max, const char* sopath) {
    return linker_pre_alloc(size, min, max, sopath);
}
#ifdef __cplusplus
}
#endif
