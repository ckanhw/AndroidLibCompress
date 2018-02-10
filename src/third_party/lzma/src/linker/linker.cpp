/*
 * Copyright (C) 2008, 2009 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <new>

#include "private/ScopedFd.h"
#include "private/ScopeGuard.h"
#include "private/UniquePtr.h"

#include "linker.h"
#include "linker_phdr.h"
#include "linker_allocator.h"


#if defined(__LP64__)
#define SEARCH_NAME(x) x
#else
// Nvidia drivers are relying on the bug:
// http://code.google.com/p/android/issues/detail?id=6670
// so we continue to use base-name lookup for lp32
static const char* get_base_name(const char* name) {
  const char* bname = strrchr(name, '/');
  return bname ? bname + 1 : name;
}
#define SEARCH_NAME(x) get_base_name(x)
#endif

static ElfW(Addr) get_elf_exec_load_bias(const ElfW(Ehdr)* elf);

static LinkerAllocator<soinfo> g_soinfo_allocator;
static LinkerAllocator<LinkedListEntry<soinfo>> g_soinfo_links_allocator;

static soinfo* solist;
static soinfo* sonext;
static soinfo* somain; // main process, always the one after libdl_info

static const char* const kDefaultLdPaths[] = {
#if defined(__LP64__)
  "/vendor/lib64",
  "/system/lib64",
#else
  "/vendor/lib",
  "/system/lib",
#endif
  nullptr
};

#define LDPATH_BUFSIZE (LDPATH_MAX*64)
#define LDPATH_MAX 8

#define LDPRELOAD_BUFSIZE (LDPRELOAD_MAX*64)
#define LDPRELOAD_MAX 8

static char g_ld_library_paths_buffer[LDPATH_BUFSIZE];
static const char* g_ld_library_paths[LDPATH_MAX + 1];

static char g_ld_preloads_buffer[LDPRELOAD_BUFSIZE];
static const char* g_ld_preload_names[LDPRELOAD_MAX + 1];

static soinfo* g_ld_preloads[LDPRELOAD_MAX + 1];

#define TRACE_TYPE
#define LOOKUP
#define RTLD_NOLOAD 4
#define __libc_fatal

#include <android/log.h>
#define LOG_TAG    "testhook"
//#define TRACE(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,__VA_ARGS__)
//#define INFO(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,__VA_ARGS__)
//#define PRINT(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG,__VA_ARGS__)
//#define DEBUG(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG,__VA_ARGS__)
//#define DL_WARN(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG,__VA_ARGS__)

#define  LOGI(...)  //__android_log_print(ANDROID_LOG_INFO, LOG_TAG,__VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,__VA_ARGS__)
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG,__VA_ARGS__)
#define  DEBUG(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,__VA_ARGS__)

#define TRACE(...)
#define INFO(...)
#define PRINT(...)
#define DL_WARN(...)
#define DL_DEBUG(...)

typedef unsigned char Byte;

enum RelocationKind {
  kRelocAbsolute = 0,
  kRelocRelative,
  kRelocCopy,
  kRelocSymbol,
  kRelocMax
};

#if STATS
struct linker_stats_t {
  int count[kRelocMax];
};

static linker_stats_t linker_stats;

static void count_relocation(RelocationKind kind) {
  ++linker_stats.count[kind];
}
#else
static void count_relocation(RelocationKind) {
}
#endif

#if COUNT_PAGES
static unsigned bitmask[4096];
#if defined(__LP64__)
#define MARK(offset) \
    do { \
      if ((((offset) >> 12) >> 5) < 4096) \
          bitmask[((offset) >> 12) >> 5] |= (1 << (((offset) >> 12) & 31)); \
    } while (0)
#else
#define MARK(offset) \
    do { \
      bitmask[((offset) >> 12) >> 3] |= (1 << (((offset) >> 12) & 7)); \
    } while (0)
#endif
#else
#define MARK(x) do {} while (0)
#endif

extern "C" {
bool from_file = false;
extern struct MergeData* g_merge;
}

// This function is an empty stub where GDB locates a breakpoint to get notified
// about linker activity.
extern "C" void __attribute__((noinline)) __attribute__((visibility("default"))) rtld_db_dlactivity();

LinkedListEntry<soinfo>* SoinfoListAllocator::alloc() {
  return g_soinfo_links_allocator.alloc();
}

void SoinfoListAllocator::free(LinkedListEntry<soinfo>* entry) {
  g_soinfo_links_allocator.free(entry);
}

static void protect_data(int protection) {
  g_soinfo_allocator.protect_all(protection);
  g_soinfo_links_allocator.protect_all(protection);
}

static soinfo* soinfo_alloc(const char* name, struct stat* file_stat, off64_t file_offset) {
  if (strlen(name) >= SOINFO_NAME_LEN) {
    LOGE("library name \"%s\" too long", name);
    return nullptr;
  }

  soinfo* si = new (g_soinfo_allocator.alloc()) soinfo(name, file_stat, file_offset);

  TRACE("name %s: allocated soinfo @ %p", name, si);
  return si;
}

static void soinfo_free(soinfo* si) {
  if (si == nullptr) {
    return;
  }

  if (si->base != 0 && si->size != 0) {
    munmap(reinterpret_cast<void*>(si->base), si->size);
  }

  soinfo *prev = nullptr, *trav;

  TRACE("name %s: freeing soinfo @ %p", si->name, si);

  for (trav = solist; trav != nullptr; trav = trav->next) {
    if (trav == si) {
      break;
    }
    prev = trav;
  }
  if (trav == nullptr) {
    // si was not in solist
    LOGE("name \"%s\" is not in solist!", si->name);
    return;
  }

  // clear links to/from si
  si->remove_all_links();

  // prev will never be null, because the first entry in solist is
  // always the static libdl_info.
  prev->next = si->next;

  g_soinfo_allocator.free(si);
}


static void parse_path(const char* path, const char* delimiters,
                       const char** array, char* buf, size_t buf_size, size_t max_count) {
  if (path == nullptr) {
    return;
  }

  size_t len = strlcpy(buf, path, buf_size);

  size_t i = 0;
  char* buf_p = buf;
  while (i < max_count && (array[i] = strsep(&buf_p, delimiters))) {
    if (*array[i] != '\0') {
      ++i;
    }
  }

  // Forget the last path if we had to truncate; this occurs if the 2nd to
  // last char isn't '\0' (i.e. wasn't originally a delimiter).
  if (i > 0 && len >= buf_size && buf[buf_size - 2] != '\0') {
    array[i - 1] = nullptr;
  } else {
    array[i] = nullptr;
  }
}

static void parse_LD_LIBRARY_PATH(const char* path) {
  parse_path(path, ":", g_ld_library_paths,
             g_ld_library_paths_buffer, sizeof(g_ld_library_paths_buffer), LDPATH_MAX);
}

static void parse_LD_PRELOAD(const char* path) {
  // We have historically supported ':' as well as ' ' in LD_PRELOAD.
  parse_path(path, " :", g_ld_preload_names,
             g_ld_preloads_buffer, sizeof(g_ld_preloads_buffer), LDPRELOAD_MAX);
}

#if defined(__arm__)
// For a given PC, find the .so that it belongs to.
// Returns the base address of the .ARM.exidx section
// for that .so, and the number of 8-byte entries
// in that section (via *pcount).
//
// Intended to be called by libc's __gnu_Unwind_Find_exidx().
//
// This function is exposed via dlfcn.cpp and libdl.so.
_Unwind_Ptr my_dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount, soinfo* si) {
    unsigned addr = (unsigned)pc;
    *pcount = si->ARM_exidx_count;
    return (_Unwind_Ptr)si->ARM_exidx;
}

#endif

//// Here, we only have to provide a callback to iterate across all the
//// loaded libraries. gcc_eh does the rest.
//int dl_iterate_phdr(int (*cb)(dl_phdr_info* info, size_t size, void* data), void* data) {
//  int rv = 0;
//  for (soinfo* si = solist; si != nullptr; si = si->next) {
//    dl_phdr_info dl_info;
//    dl_info.dlpi_addr = si->link_map_head.l_addr;
//    dl_info.dlpi_name = si->link_map_head.l_name;
//    dl_info.dlpi_phdr = si->phdr;
//    dl_info.dlpi_phnum = si->phnum;
//    rv = cb(&dl_info, sizeof(dl_phdr_info), data);
//    if (rv != 0) {
//      break;
//    }
//  }
//  return rv;
//}

static bool is_symbol_global_and_defined(const soinfo* si, const ElfW(Sym)* s) {
  if (ELF_ST_BIND(s->st_info) == STB_GLOBAL ||
      ELF_ST_BIND(s->st_info) == STB_WEAK) {
    return s->st_shndx != SHN_UNDEF;
  } else if (ELF_ST_BIND(s->st_info) != STB_LOCAL) {
    DL_WARN("unexpected ST_BIND value: %d for '%s' in '%s'",
        ELF_ST_BIND(s->st_info), si->get_string(s->st_name), si->name);
  }

  return false;
}

static uint32_t gnu_hash(const char* name) {
    uint32_t h = 5381;
    const uint8_t* tname = reinterpret_cast<const uint8_t*>(name);
    while (*tname != 0) {
      h += (h << 5) + *tname++; // h*33 + c = h + h * 32 + c = h + h << 5 + c
    }

    return h;
}

ElfW(Sym)* soinfo::gnu_lookup(unsigned hashh, const char* name) {
  unsigned hash =  gnu_hash(name);
  uint32_t h2 = hash >> gnu_shift2_;
  uint32_t bloom_mask_bits = sizeof(ElfW(Addr))*8;
  uint32_t word_num = (hash / bloom_mask_bits) & gnu_maskwords_;
  ElfW(Addr) bloom_word = gnu_bloom_filter_[word_num];

//  *symbol_index = 0;

  LOGD("SEARCH %s in %s@%p (gnu)",
      name, "get_realpath()", reinterpret_cast<void*>(base));

  // test against bloom filter
  if ((1 & (bloom_word >> (hash % bloom_mask_bits)) & (bloom_word >> (h2 % bloom_mask_bits))) == 0) {
    LOGD("NOT FOUND %s in %s@%p",
        name, "get_realpath()", reinterpret_cast<void*>(base));

    return nullptr;
  }

  // bloom test says "probably yes"...
  uint32_t n = gnu_bucket_[hash % gnu_nbucket_];
  if (n == 0) {
      LOGD("NOT FOUND %s in %s@%p",
        name, "get_realpath()", reinterpret_cast<void*>(base));

    return nullptr;
  }

  // lookup versym for the version definition in this library
  // note the difference between "version is not requested" (vi == nullptr)
  // and "version not found". In the first case verneed is kVersymNotNeeded
  // which implies that the default version can be accepted; the second case results in
  // verneed = 1 (kVersymGlobal) and implies that we should ignore versioned symbols
  // for this library and consider only *global* ones.
//  ElfW(Versym) verneed = 0;
//  if (!find_verdef_version_index(vi, &verneed)) {
//    return false;
//  }

  do {
    ElfW(Sym)* s = symtab + n;
    LOGE("check %s", get_string(s->st_name));
//    const ElfW(Versym)* verdef = get_versym(n);
//    // skip hidden versions when verneed == kVersymNotNeeded (0)
//    if (verneed == kVersymNotNeeded && is_versym_hidden(verdef)) {
//        continue;
//    }
    if (((gnu_chain_[n] ^ hash) >> 1) == 0 &&
//        check_symbol_version(verneed, verdef) &&
        strcmp(get_string(s->st_name), name) == 0 &&
        is_symbol_global_and_defined(this, s)) {
        LOGD("FOUND %s in %s (%p) %zd",
          name, "get_realpath()", reinterpret_cast<void*>(s->st_value),
          static_cast<size_t>(s->st_size));
//      *symbol_index = n;
      return s;
    }
  } while ((gnu_chain_[n++] & 1) == 0);

  LOGD("NOT FOUND %s in %s@%p",
             name, "get_realpath()", reinterpret_cast<void*>(base));

  return nullptr;
}

static bool is_gnu_hash(soinfo* si) {
  return (si->flags & FLAG_GNU_HASH) != 0;
}

static ElfW(Sym)* soinfo_elf_lookup(soinfo* si, unsigned hash, const char* name) {
  ElfW(Sym)* symtab = si->symtab;

//  TRACE_TYPE(LOOKUP, "SEARCH %s in %s@%p %x %zd",
//             name, si->name, reinterpret_cast<void*>(si->base), hash, hash % si->nbucket);

  if (is_gnu_hash(si)) {
      return si->gnu_lookup(hash, name);
  }

  for (unsigned n = si->bucket[hash % si->nbucket]; n != 0; n = si->chain[n]) {
    ElfW(Sym)* s = symtab + n;
    if (strcmp(si->get_string(s->st_name), name)) continue;

    // only concern ourselves with global and weak symbol definitions
    switch (ELF_ST_BIND(s->st_info)) {
      case STB_GLOBAL:
      case STB_WEAK:
        if (s->st_shndx == SHN_UNDEF) {
          continue;
        }

//        TRACE_TYPE(LOOKUP, "FOUND %s in %s (%p) %zd",
//                 name, si->name, reinterpret_cast<void*>(s->st_value),
//                 static_cast<size_t>(s->st_size));

        return s;
      case STB_LOCAL:
        continue;
      default:
        __libc_fatal("ERROR: Unexpected ST_BIND value: %d for '%s' in '%s'",
            ELF_ST_BIND(s->st_info), name, si->name);
    }
  }

//  TRACE_TYPE(LOOKUP, "NOT FOUND %s in %s@%p %x %zd",
//             name, si->name, reinterpret_cast<void*>(si->base), hash, hash % si->nbucket);


  return nullptr;
}

soinfo::soinfo(const char* name, const struct stat* file_stat, off64_t file_offset) {
  memset(this, 0, sizeof(*this));

  strlcpy(this->name, name, sizeof(this->name));
  flags = FLAG_NEW_SOINFO;
  version = SOINFO_VERSION;

  if (file_stat != nullptr) {
    this->st_dev = file_stat->st_dev;
    this->st_ino = file_stat->st_ino;
    this->file_offset = file_offset;
  }
}

static unsigned elfhash(const char* _name) {
  const unsigned char* name = reinterpret_cast<const unsigned char*>(_name);
  unsigned h = 0, g;

  while (*name) {
    h = (h << 4) + *name++;
    g = h & 0xf0000000;
    h ^= g;
    h ^= g >> 24;
  }
  return h;
}

static ElfW(Sym)* soinfo_do_lookup(soinfo* si, const char* name, soinfo** lsi) {
  unsigned elf_hash = elfhash(name);
  ElfW(Sym)* s = nullptr;

  /* "This element's presence in a shared object library alters the dynamic linker's
   * symbol resolution algorithm for references within the library. Instead of starting
   * a symbol search with the executable file, the dynamic linker starts from the shared
   * object itself. If the shared object fails to supply the referenced symbol, the
   * dynamic linker then searches the executable file and other shared objects as usual."
   *
   * http://www.sco.com/developers/gabi/2012-12-31/ch5.dynamic.html
   *
   * Note that this is unlikely since static linker avoids generating
   * relocations for -Bsymbolic linked dynamic executables.
   */
  if (si->has_DT_SYMBOLIC) {
    DL_DEBUG("%s: looking up %s in local scope (DT_SYMBOLIC)", si->name, name);
    s = soinfo_elf_lookup(si, elf_hash, name);
    if (s != nullptr) {
      *lsi = si;
    }
  }

  if (s == nullptr && somain != nullptr) {
    // 1. Look for it in the main executable unless we already did.
    if (si != somain || !si->has_DT_SYMBOLIC) {
      DL_DEBUG("%s: looking up %s in executable %s",
            si->name, name, somain->name);
      s = soinfo_elf_lookup(somain, elf_hash, name);
      if (s != nullptr) {
        *lsi = somain;
      }
    }

    // 2. Look for it in the ld_preloads
    if (s == nullptr) {
      for (int i = 0; g_ld_preloads[i] != NULL; i++) {
        s = soinfo_elf_lookup(g_ld_preloads[i], elf_hash, name);
        if (s != nullptr) {
          *lsi = g_ld_preloads[i];
          break;
        }
      }
    }
  }

  /* Look for symbols in the local scope (the object who is
   * searching). This happens with C++ templates on x86 for some
   * reason.
   *
   * Notes on weak symbols:
   * The ELF specs are ambiguous about treatment of weak definitions in
   * dynamic linking.  Some systems return the first definition found
   * and some the first non-weak definition.   This is system dependent.
   * Here we return the first definition found for simplicity.  */

  if (s == nullptr && !si->has_DT_SYMBOLIC) {
    DL_DEBUG("%s: looking up %s in local scope", si->name, name);
    s = soinfo_elf_lookup(si, elf_hash, name);
    if (s != nullptr) {
      *lsi = si;
    }
  }

  if (s == nullptr) {
    si->get_children().visit([&](soinfo* child) {
      DL_DEBUG("%s: looking up %s in %s", si->name, name, child->name);
      s = soinfo_elf_lookup(child, elf_hash, name);
      if (s != nullptr) {
        *lsi = child;
        return false;
      }
      return true;
    });
  }

  if (s != nullptr) {
    DL_DEBUG("si %s sym %s s->st_value = %p, found in %s, base = %p, load bias = %p",
               si->name, name, reinterpret_cast<void*>(s->st_value),
               (*lsi)->name, reinterpret_cast<void*>((*lsi)->base),
               reinterpret_cast<void*>((*lsi)->load_bias));
  }

  return s;
}

// Each size has it's own allocator.
template<size_t size>
class SizeBasedAllocator {
 public:
  static void* alloc() {
    return allocator_.alloc();
  }

  static void free(void* ptr) {
    allocator_.free(ptr);
  }

 private:
  static LinkerBlockAllocator allocator_;
};

template<size_t size>
LinkerBlockAllocator SizeBasedAllocator<size>::allocator_(size);

template<typename T>
class TypeBasedAllocator {
 public:
  static T* alloc() {
    return reinterpret_cast<T*>(SizeBasedAllocator<sizeof(T)>::alloc());
  }

  static void free(T* ptr) {
    SizeBasedAllocator<sizeof(T)>::free(ptr);
  }
};

class LoadTask {
 public:
  struct deleter_t {
    void operator()(LoadTask* t) {
      TypeBasedAllocator<LoadTask>::free(t);
    }
  };

  typedef UniquePtr<LoadTask, deleter_t> unique_ptr;

  static deleter_t deleter;

  static LoadTask* create(const char* name, soinfo* needed_by) {
    LoadTask* ptr = TypeBasedAllocator<LoadTask>::alloc();
    return new (ptr) LoadTask(name, needed_by);
  }

  const char* get_name() const {
    return name_;
  }

  soinfo* get_needed_by() const {
    return needed_by_;
  }
 private:
  LoadTask(const char* name, soinfo* needed_by)
    : name_(name), needed_by_(needed_by) {}

  const char* name_;
  soinfo* needed_by_;

//  DISALLOW_IMPLICIT_CONSTRUCTORS(LoadTask);
};

LoadTask::deleter_t LoadTask::deleter;

template <typename T>
using linked_list_t = LinkedList<T, TypeBasedAllocator<LinkedListEntry<T>>>;

typedef linked_list_t<soinfo> SoinfoLinkedList;
typedef linked_list_t<const char> StringLinkedList;
typedef linked_list_t<LoadTask> LoadTaskList;

// This is used by dlsym(3).  It performs symbol lookup only within the
// specified soinfo object and its dependencies in breadth first order.
//ElfW(Sym)* dlsym_handle_lookup(soinfo* si, soinfo** found, const char* name1) {
void* dlsym_handle_lookup(soinfo* si, soinfo** found, const char* name) {
  SoinfoLinkedList visit_list;
  SoinfoLinkedList visited;

  visit_list.push_back(si);
  soinfo* current_soinfo;
  while ((current_soinfo = visit_list.pop_front()) != nullptr) {
    if (visited.contains(current_soinfo)) {
      continue;
    }

    ElfW(Sym)* result = soinfo_elf_lookup(current_soinfo, elfhash(name), name);

    if (result != nullptr) {
        *found = current_soinfo;
        unsigned bind = ELF_ST_BIND(result->st_info);
        if ((bind == STB_GLOBAL || bind == STB_WEAK) && result->st_shndx != 0) {
          return reinterpret_cast<void*>((*found)->resolve_symbol_address(result));
        }
        return nullptr;
    }
    visited.push_back(current_soinfo);

    current_soinfo->get_children().for_each([&](soinfo* child) {
//      visit_list.push_back(child);
    });
  }

  return nullptr;
}

/* This is used by dlsym(3) to performs a global symbol lookup. If the
   start value is null (for RTLD_DEFAULT), the search starts at the
   beginning of the global solist. Otherwise the search starts at the
   specified soinfo (for RTLD_NEXT).
 */
ElfW(Sym)* dlsym_linear_lookup(const char* name, soinfo** found, soinfo* start) {
  unsigned elf_hash = elfhash(name);

  if (start == nullptr) {
    start = solist;
  }

  ElfW(Sym)* s = nullptr;
  for (soinfo* si = start; (s == nullptr) && (si != nullptr); si = si->next) {
    s = soinfo_elf_lookup(si, elf_hash, name);
    if (s != nullptr) {
      *found = si;
      break;
    }
  }

  if (s != nullptr) {
//    TRACE_TYPE(LOOKUP, "%s s->st_value = %p, found->base = %p",
//               name, reinterpret_cast<void*>(s->st_value), reinterpret_cast<void*>((*found)->base));
  }

  return s;
}

soinfo* find_containing_library(const void* p) {
  ElfW(Addr) address = reinterpret_cast<ElfW(Addr)>(p);
  for (soinfo* si = solist; si != nullptr; si = si->next) {
    if (address >= si->base && address - si->base < si->size) {
      return si;
    }
  }
  return nullptr;
}

ElfW(Sym)* dladdr_find_symbol(soinfo* si, const void* addr) {
  ElfW(Addr) soaddr = reinterpret_cast<ElfW(Addr)>(addr) - si->base;

  // Search the library's symbol table for any defined symbol which
  // contains this address.
  for (size_t i = 0; i < si->nchain; ++i) {
    ElfW(Sym)* sym = &si->symtab[i];
    if (sym->st_shndx != SHN_UNDEF &&
        soaddr >= sym->st_value &&
        soaddr < sym->st_value + sym->st_size) {
      return sym;
    }
  }

  return nullptr;
}

static int open_library_on_path(const char* name, const char* const paths[]) {
  char buf[512];
  for (size_t i = 0; paths[i] != nullptr; ++i) {
//    int n = __libc_format_buffer(buf, sizeof(buf), "%s/%s", paths[i], name);
//    if (n < 0 || n >= static_cast<int>(sizeof(buf))) {
//      PRINT("Warning: ignoring very long library path: %s/%s", paths[i], name);
//      continue;
//    }
    int fd = TEMP_FAILURE_RETRY(open(buf, O_RDONLY | O_CLOEXEC));
    if (fd != -1) {
      return fd;
    }
  }
  return -1;
}

static int open_library(const char* name) {
  TRACE("[ opening %s ]", name);

  // If the name contains a slash, we should attempt to open it directly and not search the paths.
  if (strchr(name, '/') != nullptr) {
    int fd = TEMP_FAILURE_RETRY(open(name, O_RDONLY | O_CLOEXEC));
    if (fd != -1) {
      return fd;
    }
    // ...but nvidia binary blobs (at least) rely on this behavior, so fall through for now.
#if defined(__LP64__)
    return -1;
#endif
  }

  // samtestadd
  parse_LD_LIBRARY_PATH("/data/data/com.sam.test/lib/");

  LOGI("ld_library_paths : %s", g_ld_library_paths[0]);

  // Otherwise we try LD_LIBRARY_PATH first, and fall back to the built-in well known paths.
  int fd = open_library_on_path(name, g_ld_library_paths);
  if (fd == -1) {
    fd = open_library_on_path(name, kDefaultLdPaths);
  }
  return fd;
}

template<typename F>
static void for_each_dt_needed(const soinfo* si, F action) {
  for (ElfW(Dyn)* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
    if (d->d_tag == DT_NEEDED) {
      action(si->get_string(d->d_un.d_val));
    }
  }
}

static soinfo* load_library(LoadTaskList& load_tasks, const char* name, int dlflags) {
    if (!g_merge) {
        LOGE("linker load_library, global data is null.");
        return nullptr;
    }

  int fd = -1;
  off64_t file_offset = 0;

  ScopedFd file_guard(-1);

  if (from_file) {
    // Open the file.
    fd = open_library(name);

    if (fd == -1) {
      LOGE("library \"%s\" not found", name);
      return nullptr;
    }

    file_guard.reset(fd);
  }


  if ((file_offset % PAGE_SIZE) != 0) {
    LOGE("file offset for the library \"%s\" is not page-aligned: %", name, file_offset);
    return nullptr;
  }

  struct stat file_stat;
  if (fd != -1 && TEMP_FAILURE_RETRY(fstat(fd, &file_stat)) != 0) {
    LOGE("unable to stat file for the library \"%s\": %s", name, strerror(errno));
    return nullptr;
  }

  if ((dlflags & RTLD_NOLOAD) != 0) {
    LOGE("library \"%s\" wasn't loaded and RTLD_NOLOAD prevented it", name);
    return nullptr;
  }

  // Read the ELF header and load the segments.
  ElfReader elf_reader(name, fd, file_offset, g_merge->start, g_merge->bias, g_merge->load_size);
  if (!elf_reader.Load()) {
    return nullptr;
  }

  soinfo* si = soinfo_alloc(SEARCH_NAME(name), &file_stat, file_offset);
  if (si == nullptr) {
    return nullptr;
  }
  si->base = elf_reader.load_start();
  si->size = elf_reader.load_size();
  si->load_bias = elf_reader.load_bias();
  si->phnum = elf_reader.phdr_count();
  si->phdr = elf_reader.loaded_phdr();

  g_merge->text_size = elf_reader.text_size();
  g_merge->other_start = elf_reader.other_start();

  if (!si->PrelinkImage()) {
    soinfo_free(si);
    return nullptr;
  }

  for_each_dt_needed(si, [&] (const char* name) {
      load_tasks.push_back(LoadTask::create(name, si));
  });

  return si;
}

static soinfo *find_loaded_library_by_name(const char* name) {
  const char* search_name = SEARCH_NAME(name);
  for (soinfo* si = solist; si != nullptr; si = si->next) {
    if (!strcmp(search_name, si->name)) {
      return si;
    }
  }
  return nullptr;
}

static soinfo* find_library_internal(LoadTaskList& load_tasks, const char* name, int dlflags) {

  soinfo* si = find_loaded_library_by_name(name);

  // Library might still be loaded, the accurate detection
  // of this fact is done by load_library.
  if (si == nullptr) {
    TRACE("[ '%s' has not been found by name.  Trying harder...]", name);
    si = load_library(load_tasks, name, dlflags);
  }

  return si;
}

static uint32_t get_module_base(pid_t pid, char *module_path) {
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
        LOGI("open %s failed!", filename);
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module_path)) {
            pch = strtok(line, "-");
            addr = strtoul(pch, NULL, 16);

//            char* str = NULL;
//            char* origin = line;
//            char* dest = NULL;
//            do {
//                 str = strtok(origin, " ");
//                 printf("strs %s\n", str);
//                 if(str != NULL) {
//                     dest = str;
//                 }
//                 origin = NULL;
//            } while(str!=NULL);
//            sprintf(module_path, "%s", dest);

            break;
        }
    }

    fclose(fp);
    return addr;
}

static soinfo* construct_soinfo(const char* name, int dlflags) {
    soinfo* handle = (soinfo*)dlopen(name, RTLD_LAZY);
    LOGD("dlopen %s, %p", name, handle);

    return handle;
}

static void soinfo_unload(soinfo* si);

static bool is_recursive(soinfo* si, soinfo* parent) {
  if (parent == nullptr) {
    return false;
  }

  if (si == parent) {
    LOGE("recursive link to \"%s\"", si->name);
    return true;
  }

  return !parent->get_parents().visit([&](soinfo* grandparent) {
    return !is_recursive(si, grandparent);
  });
}

static bool find_libraries(const char* const library_names[], size_t library_names_size, soinfo* soinfos[],
    soinfo* ld_preloads[], size_t ld_preloads_size, int dlflags) {
  // Step 0: prepare.
  LoadTaskList load_tasks;
  for (size_t i = 0; i < library_names_size; ++i) {
    const char* name = library_names[i];
    load_tasks.push_back(LoadTask::create(name, nullptr));
  }

  // Libraries added to this list in reverse order so that we can
  // start linking from bottom-up - see step 2.
  SoinfoLinkedList found_libs;
  size_t soinfos_size = 0;

  soinfo* root = nullptr; // change

  auto failure_guard = make_scope_guard([&]() {
    // Housekeeping
    load_tasks.for_each([] (LoadTask* t) {
      LoadTask::deleter(t);
    });

//    for (size_t i = 0; i<soinfos_size; ++i) {
//      soinfo_unload(soinfos[i]);
//    }

      soinfo_free(root);
  });

  // Step 1: load and pre-link all DT_NEEDED libraries in breadth first order.
  for (LoadTask::unique_ptr task(load_tasks.pop_front()); task.get() != nullptr; task.reset(load_tasks.pop_front())) {
      soinfo* si = nullptr;
      if (root) {
          si = construct_soinfo(task->get_name(), dlflags);
      } else {
          si = find_library_internal(load_tasks, task->get_name(), dlflags);
      }
      if (si == nullptr) {
          return false;
      }

      // change
      if (!root) {
          si->ref_count = 1;
      }

      soinfo* needed_by = task->get_needed_by();

      if (needed_by != nullptr) {
           needed_by->add_child(si);
      }
      found_libs.push_front(si);

    // When ld_preloads is not null first
    // ld_preloads_size libs are in fact ld_preloads.
    if (ld_preloads != nullptr && soinfos_size < ld_preloads_size) {
      ld_preloads[soinfos_size] = si;
    }

    if (!root && soinfos_size<library_names_size) {
      soinfos[soinfos_size++] = si;
    }

    if (!root) {
        root = si;
    }
  }

  // Step 2: link libraries.
  soinfo* si;
  while ((si = found_libs.pop_front()) != nullptr) {
    if ((si->flags & FLAG_LINKED) == 0) {
      if (!si->LinkImage()) {
        return false;
      }
      si->flags |= FLAG_LINKED;

      // only liname.so will be linked
      break;
    }
  }

  // All is well - found_libs and load_tasks are empty at this point
  // and all libs are successfully linked.
  failure_guard.disable();
  return true;
}

static soinfo* find_library(const char* name, int dlflags) {
  if (name == nullptr) {
      return nullptr;
  }

  soinfo* si;
  if (!find_libraries(&name, 1, &si, nullptr, 0, dlflags)) {
    return nullptr;
  }

  return si;
}

static void soinfo_unload(soinfo* si) {
  if (si->ref_count == 1) {
    TRACE("unloading '%s'", si->name);
    si->CallDestructors();

    if (si->has_min_version(0)) {
      soinfo* child = nullptr;
      while ((child = si->get_children().pop_front()) != nullptr) {
        TRACE("%s needs to unload %s", si->name, child->name);
        soinfo_unload(child);
      }
    } else {
      for_each_dt_needed(si, [&] (const char* library_name) {
        TRACE("deprecated (old format of soinfo): %s needs to unload %s", si->name, library_name);
        soinfo* needed = find_library(library_name, RTLD_NOLOAD);
        if (needed != nullptr) {
          soinfo_unload(needed);
        } else {
          // Not found: for example if symlink was deleted between dlopen and dlclose
          // Since we cannot really handle errors at this point - print and continue.
          PRINT("warning: couldn't find %s needed by %s on unload.", library_name, si->name);
        }
      });
    }

//    notify_gdb_of_unload(si);
    si->ref_count = 0;
    soinfo_free(si);
  } else {
    si->ref_count--;
    TRACE("not unloading '%s', decrementing ref_count to %zd", si->name, si->ref_count);
  }
}

//void do_android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size) {
//  // Use basic string manipulation calls to avoid snprintf.
//  // snprintf indirectly calls pthread_getspecific to get the size of a buffer.
//  // When debug malloc is enabled, this call returns 0. This in turn causes
//  // snprintf to do nothing, which causes libraries to fail to load.
//  // See b/17302493 for further details.
//  // Once the above bug is fixed, this code can be modified to use
//  // snprintf again.
//  size_t required_len = strlen(kDefaultLdPaths[0]) + strlen(kDefaultLdPaths[1]) + 2;
//  if (buffer_size < required_len) {
//    __libc_fatal("android_get_LD_LIBRARY_PATH failed, buffer too small: buffer len %zu, required len %zu",
//                 buffer_size, required_len);
//  }
//  char* end = stpcpy(buffer, kDefaultLdPaths[0]);
//  *end = ':';
//  strcpy(end + 1, kDefaultLdPaths[1]);
//}
//
//void do_android_update_LD_LIBRARY_PATH(const char* ld_library_path) {
//  if (!get_AT_SECURE()) {
//    parse_LD_LIBRARY_PATH(ld_library_path);
//  }
//}


void cleanup() {

}

soinfo* do_dlopen(const char* name, int flags) {
  // art/runtime/jni_internal.cc, flags always be RTLD_LAZY, extinfo be null
  if ((flags & ~(RTLD_NOW|RTLD_LAZY|RTLD_LOCAL|RTLD_GLOBAL|RTLD_NOLOAD)) != 0) {
    LOGE("invalid flags to dlopen: %x", flags);
    return nullptr;
  }

  protect_data(PROT_READ | PROT_WRITE);
  soinfo* si = find_library(name, flags);
  if (si != nullptr) {
    if (solist != nullptr) {
        si->next = solist;
    } else {
        si->next = nullptr;
    }
    solist = si;
    si->CallConstructors();
  }
  protect_data(PROT_READ);

  if (si == nullptr) {
      cleanup();
  }
  return si;
}

void do_dlclose(soinfo* si) {
  protect_data(PROT_READ | PROT_WRITE);
  soinfo_unload(si);
  protect_data(PROT_READ);
}

static ElfW(Addr) call_ifunc_resolver(ElfW(Addr) resolver_addr) {
  typedef ElfW(Addr) (*ifunc_resolver_t)(void);
  ifunc_resolver_t ifunc_resolver = reinterpret_cast<ifunc_resolver_t>(resolver_addr);
  ElfW(Addr) ifunc_addr = ifunc_resolver();
//  TRACE_TYPE(RELO, "Called ifunc_resolver@%p. The result is %p", ifunc_resolver, reinterpret_cast<void*>(ifunc_addr));

  return ifunc_addr;
}

#if defined(USE_RELA)
int soinfo::Relocate(ElfW(Rela)* rela, unsigned count) {
  for (size_t idx = 0; idx < count; ++idx, ++rela) {
    unsigned type = ELFW(R_TYPE)(rela->r_info);
    unsigned sym = ELFW(R_SYM)(rela->r_info);
    ElfW(Addr) reloc = static_cast<ElfW(Addr)>(rela->r_offset + load_bias);
    ElfW(Addr) sym_addr = 0;
    const char* sym_name = nullptr;

    DL_DEBUG("Processing '%s' relocation at index %zd", name, idx);
    if (type == 0) { // R_*_NONE
      continue;
    }

    ElfW(Sym)* s = nullptr;
    soinfo* lsi = nullptr;

    if (sym != 0) {
      sym_name = get_string(symtab[sym].st_name);
      s = soinfo_do_lookup(this, sym_name, &lsi);
      if (s == nullptr) {
        // We only allow an undefined symbol if this is a weak reference...
        s = &symtab[sym];
        if (ELF_ST_BIND(s->st_info) != STB_WEAK) {
          LOGE("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name, name);
          return -1;
        }

        /* IHI0044C AAELF 4.5.1.1:

           Libraries are not searched to resolve weak references.
           It is not an error for a weak reference to remain unsatisfied.

           During linking, the value of an undefined weak reference is:
           - Zero if the relocation type is absolute
           - The address of the place if the relocation is pc-relative
           - The address of nominal base address if the relocation
             type is base-relative.
         */

        switch (type) {
#if defined(__aarch64__)
          case R_AARCH64_JUMP_SLOT:
          case R_AARCH64_GLOB_DAT:
          case R_AARCH64_ABS64:
          case R_AARCH64_ABS32:
          case R_AARCH64_ABS16:
          case R_AARCH64_RELATIVE:
          case R_AARCH64_IRELATIVE:
            /*
             * The sym_addr was initialized to be zero above, or the relocation
             * code below does not care about value of sym_addr.
             * No need to do anything.
             */
            break;
#elif defined(__x86_64__)
          case R_X86_64_JUMP_SLOT:
          case R_X86_64_GLOB_DAT:
          case R_X86_64_32:
          case R_X86_64_64:
          case R_X86_64_RELATIVE:
          case R_X86_64_IRELATIVE:
            // No need to do anything.
            break;
          case R_X86_64_PC32:
            sym_addr = reloc;
            break;
#endif
          default:
            LOGE("unknown weak reloc type %d @ %p (%zu)", type, rela, idx);
            return -1;
        }
      } else {
        // We got a definition.
        sym_addr = lsi->resolve_symbol_address(s);
      }
      count_relocation(kRelocSymbol);
    }

    switch (type) {
#if defined(__aarch64__)
      case R_AARCH64_JUMP_SLOT:
        count_relocation(kRelocAbsolute);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO JMP_SLOT %16llx <- %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + rela->r_addend);
        break;
      case R_AARCH64_GLOB_DAT:
        count_relocation(kRelocAbsolute);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO GLOB_DAT %16llx <- %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + rela->r_addend);
        break;
      case R_AARCH64_ABS64:
        count_relocation(kRelocAbsolute);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO ABS64 %16llx <- %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) += (sym_addr + rela->r_addend);
        break;
      case R_AARCH64_ABS32:
        count_relocation(kRelocAbsolute);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO ABS32 %16llx <- %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), sym_name);
        if ((static_cast<ElfW(Addr)>(INT32_MIN) <= (*reinterpret_cast<ElfW(Addr)*>(reloc) + (sym_addr + rela->r_addend))) &&
            ((*reinterpret_cast<ElfW(Addr)*>(reloc) + (sym_addr + rela->r_addend)) <= static_cast<ElfW(Addr)>(UINT32_MAX))) {
          *reinterpret_cast<ElfW(Addr)*>(reloc) += (sym_addr + rela->r_addend);
        } else {
          LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
                 (*reinterpret_cast<ElfW(Addr)*>(reloc) + (sym_addr + rela->r_addend)),
                 static_cast<ElfW(Addr)>(INT32_MIN),
                 static_cast<ElfW(Addr)>(UINT32_MAX));
          return -1;
        }
        break;
      case R_AARCH64_ABS16:
        count_relocation(kRelocAbsolute);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO ABS16 %16llx <- %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), sym_name);
        if ((static_cast<ElfW(Addr)>(INT16_MIN) <= (*reinterpret_cast<ElfW(Addr)*>(reloc) + (sym_addr + rela->r_addend))) &&
            ((*reinterpret_cast<ElfW(Addr)*>(reloc) + (sym_addr + rela->r_addend)) <= static_cast<ElfW(Addr)>(UINT16_MAX))) {
          *reinterpret_cast<ElfW(Addr)*>(reloc) += (sym_addr + rela->r_addend);
        } else {
          LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
                 (*reinterpret_cast<ElfW(Addr)*>(reloc) + (sym_addr + rela->r_addend)),
                 static_cast<ElfW(Addr)>(INT16_MIN),
                 static_cast<ElfW(Addr)>(UINT16_MAX));
          return -1;
        }
        break;
      case R_AARCH64_PREL64:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO REL64 %16llx <- %16llx - %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), rela->r_offset, sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) += (sym_addr + rela->r_addend) - rela->r_offset;
        break;
      case R_AARCH64_PREL32:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO REL32 %16llx <- %16llx - %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), rela->r_offset, sym_name);
        if ((static_cast<ElfW(Addr)>(INT32_MIN) <= (*reinterpret_cast<ElfW(Addr)*>(reloc) + ((sym_addr + rela->r_addend) - rela->r_offset))) &&
            ((*reinterpret_cast<ElfW(Addr)*>(reloc) + ((sym_addr + rela->r_addend) - rela->r_offset)) <= static_cast<ElfW(Addr)>(UINT32_MAX))) {
          *reinterpret_cast<ElfW(Addr)*>(reloc) += ((sym_addr + rela->r_addend) - rela->r_offset);
        } else {
          LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
                 (*reinterpret_cast<ElfW(Addr)*>(reloc) + ((sym_addr + rela->r_addend) - rela->r_offset)),
                 static_cast<ElfW(Addr)>(INT32_MIN),
                 static_cast<ElfW(Addr)>(UINT32_MAX));
          return -1;
        }
        break;
      case R_AARCH64_PREL16:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO REL16 %16llx <- %16llx - %16llx %s\n",
                   reloc, (sym_addr + rela->r_addend), rela->r_offset, sym_name);
        if ((static_cast<ElfW(Addr)>(INT16_MIN) <= (*reinterpret_cast<ElfW(Addr)*>(reloc) + ((sym_addr + rela->r_addend) - rela->r_offset))) &&
            ((*reinterpret_cast<ElfW(Addr)*>(reloc) + ((sym_addr + rela->r_addend) - rela->r_offset)) <= static_cast<ElfW(Addr)>(UINT16_MAX))) {
          *reinterpret_cast<ElfW(Addr)*>(reloc) += ((sym_addr + rela->r_addend) - rela->r_offset);
        } else {
          LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
                 (*reinterpret_cast<ElfW(Addr)*>(reloc) + ((sym_addr + rela->r_addend) - rela->r_offset)),
                 static_cast<ElfW(Addr)>(INT16_MIN),
                 static_cast<ElfW(Addr)>(UINT16_MAX));
          return -1;
        }
        break;

      case R_AARCH64_RELATIVE:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        if (sym) {
          LOGE("odd RELATIVE form...");
          return -1;
        }
        TRACE_TYPE(RELO, "RELO RELATIVE %16llx <- %16llx\n",
                   reloc, (base + rela->r_addend));
        *reinterpret_cast<ElfW(Addr)*>(reloc) = (base + rela->r_addend);
        break;

      case R_AARCH64_IRELATIVE:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO IRELATIVE %16llx <- %16llx\n", reloc, (base + rela->r_addend));
        *reinterpret_cast<ElfW(Addr)*>(reloc) = call_ifunc_resolver(base + rela->r_addend);
        break;

      case R_AARCH64_COPY:
        /*
         * ET_EXEC is not supported so this should not happen.
         *
         * http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044d/IHI0044D_aaelf.pdf
         *
         * Section 4.7.1.10 "Dynamic relocations"
         * R_AARCH64_COPY may only appear in executable objects where e_type is
         * set to ET_EXEC.
         */
        LOGE("%s R_AARCH64_COPY relocations are not supported", name);
        return -1;
      case R_AARCH64_TLS_TPREL64:
        TRACE_TYPE(RELO, "RELO TLS_TPREL64 *** %16llx <- %16llx - %16llx\n",
                   reloc, (sym_addr + rela->r_addend), rela->r_offset);
        break;
      case R_AARCH64_TLS_DTPREL32:
        TRACE_TYPE(RELO, "RELO TLS_DTPREL32 *** %16llx <- %16llx - %16llx\n",
                   reloc, (sym_addr + rela->r_addend), rela->r_offset);
        break;
#elif defined(__x86_64__)
      case R_X86_64_JUMP_SLOT:
        count_relocation(kRelocAbsolute);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO JMP_SLOT %08zx <- %08zx %s", static_cast<size_t>(reloc),
                   static_cast<size_t>(sym_addr + rela->r_addend), sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + rela->r_addend;
        break;
      case R_X86_64_GLOB_DAT:
        count_relocation(kRelocAbsolute);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO GLOB_DAT %08zx <- %08zx %s", static_cast<size_t>(reloc),
                   static_cast<size_t>(sym_addr + rela->r_addend), sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + rela->r_addend;
        break;
      case R_X86_64_RELATIVE:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        if (sym) {
          LOGE("odd RELATIVE form...");
          return -1;
        }
        TRACE_TYPE(RELO, "RELO RELATIVE %08zx <- +%08zx", static_cast<size_t>(reloc),
                   static_cast<size_t>(base));
        *reinterpret_cast<ElfW(Addr)*>(reloc) = base + rela->r_addend;
        break;
      case R_X86_64_IRELATIVE:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO IRELATIVE %16llx <- %16llx\n", reloc, (base + rela->r_addend));
        *reinterpret_cast<ElfW(Addr)*>(reloc) = call_ifunc_resolver(base + rela->r_addend);
        break;
      case R_X86_64_32:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO R_X86_64_32 %08zx <- +%08zx %s", static_cast<size_t>(reloc),
                   static_cast<size_t>(sym_addr), sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + rela->r_addend;
        break;
      case R_X86_64_64:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO R_X86_64_64 %08zx <- +%08zx %s", static_cast<size_t>(reloc),
                   static_cast<size_t>(sym_addr), sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + rela->r_addend;
        break;
      case R_X86_64_PC32:
        count_relocation(kRelocRelative);
        MARK(rela->r_offset);
        TRACE_TYPE(RELO, "RELO R_X86_64_PC32 %08zx <- +%08zx (%08zx - %08zx) %s",
                   static_cast<size_t>(reloc), static_cast<size_t>(sym_addr - reloc),
                   static_cast<size_t>(sym_addr), static_cast<size_t>(reloc), sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + rela->r_addend - reloc;
        break;
#endif

      default:
        LOGE("unknown reloc type %d @ %p (%zu)", type, rela, idx);
        return -1;
    }
  }
  return 0;
}

#else // REL, not RELA.

_Unwind_Ptr WrapDl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount) {
    unsigned addr = (unsigned)pc;
    for (soinfo* trav = solist; trav != nullptr; trav = trav->next) {
        if (trav != nullptr && (addr >= trav->base) && (addr < (trav->base + trav->size))) {
            return my_dl_unwind_find_exidx(pc, pcount, trav);
        }
    }

    // Lookup in system libraries.
    return ::dl_unwind_find_exidx(pc, pcount);
}

ElfW(Addr) WrapLinkerSymbol(const char* name) {
    if (!strcmp("__gnu_Unwind_Find_exidx", name)) {
        return reinterpret_cast<ElfW(Addr)>(&WrapDl_unwind_find_exidx);
    }
    return 0;
}

int soinfo::Relocate(ElfW(Rel)* rel, unsigned count) {
  for (size_t idx = 0; idx < count; ++idx, ++rel) {
    unsigned type = ELFW(R_TYPE)(rel->r_info);
    // TODO: don't use unsigned for 'sym'. Use uint32_t or ElfW(Addr) instead.
    unsigned sym = ELFW(R_SYM)(rel->r_info);
    ElfW(Addr) reloc = static_cast<ElfW(Addr)>(rel->r_offset + load_bias);
    ElfW(Addr) sym_addr = 0;
    const char* sym_name = nullptr;

    DL_DEBUG("Processing '%s' relocation at index %zd", name, idx);
    if (type == 0) { // R_*_NONE
      continue;
    }

    ElfW(Sym)* s = nullptr;
    soinfo* lsi = nullptr;

    if (sym != 0) {
      sym_name = get_string(symtab[sym].st_name);

      sym_addr = WrapLinkerSymbol(sym_name);
      if (sym_addr == 0) {
          s = soinfo_do_lookup(this, sym_name, &lsi);

          if (s == nullptr) {
            // We only allow an undefined symbol if this is a weak reference...
            s = &symtab[sym];
            if (ELF_ST_BIND(s->st_info) != STB_WEAK) {
              LOGE("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name, name);
              return -1;
            }

            /* IHI0044C AAELF 4.5.1.1:

               Libraries are not searched to resolve weak references.
               It is not an error for a weak reference to remain
               unsatisfied.

               During linking, the value of an undefined weak reference is:
               - Zero if the relocation type is absolute
               - The address of the place if the relocation is pc-relative
               - The address of nominal base address if the relocation
                 type is base-relative.
            */

            switch (type) {
#if defined(__arm__)
              case R_ARM_JUMP_SLOT:
              case R_ARM_GLOB_DAT:
              case R_ARM_ABS32:
              case R_ARM_RELATIVE:    /* Don't care. */
                // sym_addr was initialized to be zero above or relocation
                // code below does not care about value of sym_addr.
                // No need to do anything.
                break;
#elif defined(__i386__)
              case R_386_JMP_SLOT:
              case R_386_GLOB_DAT:
              case R_386_32:
              case R_386_RELATIVE:    /* Don't care. */
              case R_386_IRELATIVE:
                // sym_addr was initialized to be zero above or relocation
                // code below does not care about value of sym_addr.
                // No need to do anything.
                break;
              case R_386_PC32:
                sym_addr = reloc;
                break;
#endif

#if defined(__arm__)
              case R_ARM_COPY:
                // Fall through. Can't really copy if weak symbol is not found at run-time.
#endif
              default:
                LOGE("unknown weak reloc type %d @ %p (%zu)", type, rel, idx);
                return -1;
            }
          } else {
            // We got a definition.
            sym_addr = lsi->resolve_symbol_address(s);
          }
      }
      count_relocation(kRelocSymbol);
    }

    switch (type) {
#if defined(__arm__)
      case R_ARM_JUMP_SLOT:
        count_relocation(kRelocAbsolute);
        MARK(rel->r_offset);
//        TRACE_TYPE(RELO, "RELO JMP_SLOT %08x <- %08x %s", reloc, sym_addr, sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
        break;
      case R_ARM_GLOB_DAT:
        count_relocation(kRelocAbsolute);
        MARK(rel->r_offset);
//        TRACE_TYPE(RELO, "RELO GLOB_DAT %08x <- %08x %s", reloc, sym_addr, sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
        break;
      case R_ARM_ABS32:
        count_relocation(kRelocAbsolute);
        MARK(rel->r_offset);
//        TRACE_TYPE(RELO, "RELO ABS %08x <- %08x %s", reloc, sym_addr, sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr;
        break;
      case R_ARM_REL32:
        count_relocation(kRelocRelative);
        MARK(rel->r_offset);
//        TRACE_TYPE(RELO, "RELO REL32 %08x <- %08x - %08x %s",
//                   reloc, sym_addr, rel->r_offset, sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr - rel->r_offset;
        break;
      case R_ARM_COPY:
        /*
         * ET_EXEC is not supported so this should not happen.
         *
         * http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044d/IHI0044D_aaelf.pdf
         *
         * Section 4.7.1.10 "Dynamic relocations"
         * R_ARM_COPY may only appear in executable objects where e_type is
         * set to ET_EXEC.
         */
        LOGE("%s R_ARM_COPY relocations are not supported", name);
        return -1;
#elif defined(__i386__)
      case R_386_JMP_SLOT:
        count_relocation(kRelocAbsolute);
        MARK(rel->r_offset);
//        TRACE_TYPE(RELO, "RELO JMP_SLOT %08x <- %08x %s", reloc, sym_addr, sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
        break;
      case R_386_GLOB_DAT:
        count_relocation(kRelocAbsolute);
        MARK(rel->r_offset);
//        TRACE_TYPE(RELO, "RELO GLOB_DAT %08x <- %08x %s", reloc, sym_addr, sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr;
        break;
      case R_386_32:
        count_relocation(kRelocRelative);
        MARK(rel->r_offset);
//        TRACE_TYPE(RELO, "RELO R_386_32 %08x <- +%08x %s", reloc, sym_addr, sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr;
        break;
      case R_386_PC32:
        count_relocation(kRelocRelative);
        MARK(rel->r_offset);
//        TRACE_TYPE(RELO, "RELO R_386_PC32 %08x <- +%08x (%08x - %08x) %s",
//                   reloc, (sym_addr - reloc), sym_addr, reloc, sym_name);
        *reinterpret_cast<ElfW(Addr)*>(reloc) += (sym_addr - reloc);
        break;
#elif defined(__mips__)
      case R_MIPS_REL32:
#if defined(__LP64__)
        // MIPS Elf64_Rel entries contain compound relocations
        // We only handle the R_MIPS_NONE|R_MIPS_64|R_MIPS_REL32 case
        if (ELF64_R_TYPE2(rel->r_info) != R_MIPS_64 ||
            ELF64_R_TYPE3(rel->r_info) != R_MIPS_NONE) {
          LOGE("Unexpected compound relocation type:%d type2:%d type3:%d @ %p (%zu)",
                 type, (unsigned)ELF64_R_TYPE2(rel->r_info),
                 (unsigned)ELF64_R_TYPE3(rel->r_info), rel, idx);
          return -1;
        }
#endif
        count_relocation(kRelocAbsolute);
        MARK(rel->r_offset);
//        TRACE_TYPE(RELO, "RELO REL32 %08zx <- %08zx %s", static_cast<size_t>(reloc),
//                   static_cast<size_t>(sym_addr), sym_name ? sym_name : "*SECTIONHDR*");
        if (s) {
          *reinterpret_cast<ElfW(Addr)*>(reloc) += sym_addr;
        } else {
          *reinterpret_cast<ElfW(Addr)*>(reloc) += base;
        }
        break;
#endif

#if defined(__arm__)
      case R_ARM_RELATIVE:
#elif defined(__i386__)
      case R_386_RELATIVE:
#endif
        count_relocation(kRelocRelative);
        MARK(rel->r_offset);
        if (sym) {
          LOGE("odd RELATIVE form...");
          return -1;
        }
//        TRACE_TYPE(RELO, "RELO RELATIVE %p <- +%p",
//                   reinterpret_cast<void*>(reloc), reinterpret_cast<void*>(base));
        *reinterpret_cast<ElfW(Addr)*>(reloc) += base;
        break;
#if defined(__i386__)
      case R_386_IRELATIVE:
        count_relocation(kRelocRelative);
        MARK(rel->r_offset);
//        TRACE_TYPE(RELO, "RELO IRELATIVE %p <- %p", reinterpret_cast<void*>(reloc), reinterpret_cast<void*>(base));
        *reinterpret_cast<ElfW(Addr)*>(reloc) = call_ifunc_resolver(base + *reinterpret_cast<ElfW(Addr)*>(reloc));
        break;
#endif

      default:
        LOGE("unknown reloc type %d @ %p (%zu)", type, rel, idx);
        return -1;
    }
  }
  return 0;
}
#endif

#if defined(__mips__)
static bool mips_relocate_got(soinfo* si) {
  ElfW(Addr)** got = si->plt_got;
  if (got == nullptr) {
    return true;
  }
  unsigned local_gotno = si->mips_local_gotno;
  unsigned gotsym = si->mips_gotsym;
  unsigned symtabno = si->mips_symtabno;
  ElfW(Sym)* symtab = si->symtab;

  // got[0] is the address of the lazy resolver function.
  // got[1] may be used for a GNU extension.
  // Set it to a recognizable address in case someone calls it (should be _rtld_bind_start).
  // FIXME: maybe this should be in a separate routine?
  if ((si->flags & FLAG_LINKER) == 0) {
    size_t g = 0;
    got[g++] = reinterpret_cast<ElfW(Addr)*>(0xdeadbeef);
    if (reinterpret_cast<intptr_t>(got[g]) < 0) {
      got[g++] = reinterpret_cast<ElfW(Addr)*>(0xdeadfeed);
    }
    // Relocate the local GOT entries.
    for (; g < local_gotno; g++) {
      got[g] = reinterpret_cast<ElfW(Addr)*>(reinterpret_cast<uintptr_t>(got[g]) + si->load_bias);
    }
  }

  // Now for the global GOT entries...
  ElfW(Sym)* sym = symtab + gotsym;
  got = si->plt_got + local_gotno;
  for (size_t g = gotsym; g < symtabno; g++, sym++, got++) {
    // This is an undefined reference... try to locate it.
    const char* sym_name = si->get_string(sym->st_name);
    soinfo* lsi = nullptr;
    ElfW(Sym)* s = soinfo_do_lookup(si, sym_name, &lsi);
    if (s == nullptr) {
      // We only allow an undefined symbol if this is a weak reference.
      s = &symtab[g];
      if (ELF_ST_BIND(s->st_info) != STB_WEAK) {
        LOGE("cannot locate \"%s\"...", sym_name);
        return false;
      }
      *got = 0;
    } else {
      // FIXME: is this sufficient?
      // For reference see NetBSD link loader
      // http://cvsweb.netbsd.org/bsdweb.cgi/src/libexec/ld.elf_so/arch/mips/mips_reloc.c?rev=1.53&content-type=text/x-cvsweb-markup
      *got = reinterpret_cast<ElfW(Addr)*>(lsi->resolve_symbol_address(s));
    }
  }
  return true;
}
#endif

void soinfo::CallArray(const char* array_name __unused, linker_function_t* functions, size_t count, bool reverse) {
  if (functions == nullptr) {
    return;
  }

  TRACE("[ Calling %s (size %zd) @ %p for '%s' ]", array_name, count, functions, name);

  int begin = reverse ? (count - 1) : 0;
  int end = reverse ? -1 : count;
  int step = reverse ? -1 : 1;

  for (int i = begin; i != end; i += step) {
    TRACE("[ %s[%d] == %p ]", array_name, i, functions[i]);
    CallFunction("function", functions[i]);
  }

  TRACE("[ Done calling %s for '%s' ]", array_name, name);
}

void soinfo::CallFunction(const char* function_name __unused, linker_function_t function) {
  if (function == nullptr || reinterpret_cast<uintptr_t>(function) == static_cast<uintptr_t>(-1)) {
    return;
  }

  TRACE("[ Calling %s @ %p for '%s' ]", function_name, function, name);
  function();
  TRACE("[ Done calling %s @ %p for '%s' ]", function_name, function, name);

  // The function may have called dlopen(3) or dlclose(3), so we need to ensure our data structures
  // are still writable. This happens with our debug malloc (see http://b/7941716).
  protect_data(PROT_READ | PROT_WRITE);
}

void soinfo::CallPreInitConstructors() {
  // DT_PREINIT_ARRAY functions are called before any other constructors for executables,
  // but ignored in a shared library.
  CallArray("DT_PREINIT_ARRAY", preinit_array, preinit_array_count, false);
}

void soinfo::CallConstructors() {
  if (constructors_called) {
    return;
  }

  // We set constructors_called before actually calling the constructors, otherwise it doesn't
  // protect against recursive constructor calls. One simple example of constructor recursion
  // is the libc debug malloc, which is implemented in libc_malloc_debug_leak.so:
  // 1. The program depends on libc, so libc's constructor is called here.
  // 2. The libc constructor calls dlopen() to load libc_malloc_debug_leak.so.
  // 3. dlopen() calls the constructors on the newly created
  //    soinfo for libc_malloc_debug_leak.so.
  // 4. The debug .so depends on libc, so CallConstructors is
  //    called again with the libc soinfo. If it doesn't trigger the early-
  //    out above, the libc constructor will be called again (recursively!).
  constructors_called = true;

  if ((flags & FLAG_EXE) == 0 && preinit_array != nullptr) {
    // The GNU dynamic linker silently ignores these, but we warn the developer.
    PRINT("\"%s\": ignoring %zd-entry DT_PREINIT_ARRAY in shared library!",
          name, preinit_array_count);
  }

  // samtest children already loaded, not need to callconstructors, and children soinfo page is not writable
  get_children().for_each([] (soinfo* si) {
//    si->CallConstructors();
  });

  TRACE("\"%s\": calling constructors", name);

  // DT_INIT should be called before DT_INIT_ARRAY if both are present.
  CallFunction("DT_INIT", init_func);
  CallArray("DT_INIT_ARRAY", init_array, init_array_count, false);
}

void soinfo::CallDestructors() {
  if (!constructors_called) {
    return;
  }
  TRACE("\"%s\": calling destructors", name);

  // DT_FINI_ARRAY must be parsed in reverse order.
  CallArray("DT_FINI_ARRAY", fini_array, fini_array_count, true);

  // DT_FINI should be called after DT_FINI_ARRAY if both are present.
  CallFunction("DT_FINI", fini_func);

  // This is needed on second call to dlopen
  // after library has been unloaded with RTLD_NODELETE
  constructors_called = false;
}

void soinfo::add_child(soinfo* child) {
  if (has_min_version(0)) {
//    child->parents.push_back(this);
    this->children.push_back(child);
  }
}

void soinfo::remove_all_links() {
  if (!has_min_version(0)) {
    return;
  }

  // 1. Untie connected soinfos from 'this'.
  children.for_each([&] (soinfo* child) {
    child->parents.remove_if([&] (const soinfo* parent) {
      return parent == this;
    });
  });

  parents.for_each([&] (soinfo* parent) {
    parent->children.remove_if([&] (const soinfo* child) {
      return child == this;
    });
  });

  // 2. Once everything untied - clear local lists.
  parents.clear();
  children.clear();
}

dev_t soinfo::get_st_dev() {
  if (has_min_version(0)) {
    return st_dev;
  }

  return 0;
};

ino_t soinfo::get_st_ino() {
  if (has_min_version(0)) {
    return st_ino;
  }

  return 0;
}

off64_t soinfo::get_file_offset() {
  if (has_min_version(1)) {
    return file_offset;
  }

  return 0;
}

// This is a return on get_children()/get_parents() if
// 'this->flags' does not have FLAG_NEW_SOINFO set.
static soinfo::soinfo_list_t g_empty_list;

soinfo::soinfo_list_t& soinfo::get_children() {
  if (has_min_version(0)) {
    return this->children;
  }

  return g_empty_list;
}

soinfo::soinfo_list_t& soinfo::get_parents() {
  if ((this->flags & FLAG_NEW_SOINFO) == 0) {
    return g_empty_list;
  }

  return this->parents;
}

#define STT_GNU_IFUNC 10

ElfW(Addr) soinfo::resolve_symbol_address(ElfW(Sym)* s) {
  if (ELF_ST_TYPE(s->st_info) == STT_GNU_IFUNC) {
    return call_ifunc_resolver(s->st_value + load_bias);
  }

//  return static_cast<ElfW(Addr)>(s->st_value + load_bias);
    return static_cast<ElfW(Addr)>(s->st_value + base);
}

const char* soinfo::get_string(ElfW(Word) index) const {
  if (has_min_version(1) && (index >= strtab_size)) {
    __libc_fatal("%s: strtab out of bounds error; STRSZ=%zd, name=%d", name, strtab_size, index);
  }

  return strtab + index;
}

/* Force any of the closed stdin, stdout and stderr to be associated with
   /dev/null. */
static int nullify_closed_stdio() {
  int dev_null, i, status;
  int return_value = 0;

  dev_null = TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR));
  if (dev_null < 0) {
    LOGE("cannot open /dev/null: %s", strerror(errno));
    return -1;
  }
  TRACE("[ Opened /dev/null file-descriptor=%d]", dev_null);

  /* If any of the stdio file descriptors is valid and not associated
     with /dev/null, dup /dev/null to it.  */
  for (i = 0; i < 3; i++) {
    /* If it is /dev/null already, we are done. */
    if (i == dev_null) {
      continue;
    }

    TRACE("[ Nullifying stdio file descriptor %d]", i);
    status = TEMP_FAILURE_RETRY(fcntl(i, F_GETFL));

    /* If file is opened, we are good. */
    if (status != -1) {
      continue;
    }

    /* The only error we allow is that the file descriptor does not
       exist, in which case we dup /dev/null to it. */
    if (errno != EBADF) {
      LOGE("fcntl failed: %s", strerror(errno));
      return_value = -1;
      continue;
    }

    /* Try dupping /dev/null to this stdio file descriptor and
       repeat if there is a signal.  Note that any errors in closing
       the stdio descriptor are lost.  */
    status = TEMP_FAILURE_RETRY(dup2(dev_null, i));
    if (status < 0) {
      LOGE("dup2 failed: %s", strerror(errno));
      return_value = -1;
      continue;
    }
  }

  /* If /dev/null is not one of the stdio file descriptors, close it. */
  if (dev_null > 2) {
    TRACE("[ Closing /dev/null file-descriptor=%d]", dev_null);
    status = TEMP_FAILURE_RETRY(close(dev_null));
    if (status == -1) {
      LOGE("close failed: %s", strerror(errno));
      return_value = -1;
    }
  }

  return return_value;
}

bool soinfo::PrelinkImage() {
  /* Extract dynamic section */
  ElfW(Word) dynamic_flags = 0;
  phdr_table_get_dynamic_section(phdr, phnum, load_bias, &dynamic, &dynamic_flags);

  /* We can't log anything until the linker is relocated */
  bool relocating_linker = (flags & FLAG_LINKER) != 0;
  if (!relocating_linker) {
    INFO("[ linking %s ]", name);
    DEBUG("si->base = %p si->flags = 0x%08x", reinterpret_cast<void*>(base), flags);
  }

  if (dynamic == nullptr) {
    if (!relocating_linker) {
      LOGE("missing PT_DYNAMIC in \"%s\"", name);
    }
    return false;
  } else {
    if (!relocating_linker) {
        DEBUG("dynamic = %p", dynamic);
    }
  }

#if defined(__arm__)
  (void) phdr_table_get_arm_exidx(phdr, phnum, load_bias,
                                  &ARM_exidx, &ARM_exidx_count);
#endif

  // Extract useful information from dynamic section.
  uint32_t needed_count = 0;
  for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
      DEBUG("d = %p, d[0](tag) = %p d[1](val) = %p",
          d, reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
    switch (d->d_tag) {
      case DT_SONAME:
        // TODO: glibc dynamic linker uses this name for
        // initial library lookup; consider doing the same here.
        break;

      case DT_HASH:
        nbucket = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
        nchain = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];
        bucket = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8);
        chain = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8 + nbucket * 4);
        break;

      case DT_GNU_HASH:
        gnu_nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
        // skip symndx
        gnu_maskwords_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[2];
        gnu_shift2_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[3];

        gnu_bloom_filter_ = reinterpret_cast<ElfW(Addr)*>(load_bias + d->d_un.d_ptr + 16);
        gnu_bucket_ = reinterpret_cast<uint32_t*>(gnu_bloom_filter_ + gnu_maskwords_);
        // amend chain for symndx = header[1]
        gnu_chain_ = gnu_bucket_ + gnu_nbucket_ -
            reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];

        if (!powerof2(gnu_maskwords_)) {
          LOGE("invalid maskwords for gnu_hash = 0x%x, in \"%s\" expecting power to two",
              gnu_maskwords_, "get_realpath()");
          return false;
        }
        --gnu_maskwords_;

        flags |= FLAG_GNU_HASH;
        break;

      case DT_STRTAB:
        strtab = reinterpret_cast<const char*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_STRSZ:
        strtab_size = d->d_un.d_val;
        break;

      case DT_SYMTAB:
        symtab = reinterpret_cast<ElfW(Sym)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_SYMENT:
        if (d->d_un.d_val != sizeof(ElfW(Sym))) {
          LOGE("invalid DT_SYMENT: %zd", static_cast<size_t>(d->d_un.d_val));
          return false;
        }
        break;

      case DT_PLTREL:
#if defined(USE_RELA)
        if (d->d_un.d_val != DT_RELA) {
          LOGE("unsupported DT_PLTREL in \"%s\"; expected DT_RELA", name);
          return false;
        }
#else
        if (d->d_un.d_val != DT_REL) {
          LOGE("unsupported DT_PLTREL in \"%s\"; expected DT_REL", name);
          return false;
        }
#endif
        break;

      case DT_JMPREL:
#if defined(USE_RELA)
        plt_rela = reinterpret_cast<ElfW(Rela)*>(load_bias + d->d_un.d_ptr);
#else
        plt_rel = reinterpret_cast<ElfW(Rel)*>(load_bias + d->d_un.d_ptr);
#endif
        break;

      case DT_PLTRELSZ:
#if defined(USE_RELA)
        plt_rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
#else
        plt_rel_count = d->d_un.d_val / sizeof(ElfW(Rel));
#endif
        break;

      case DT_PLTGOT:
#if defined(__mips__)
        // Used by mips and mips64.
        plt_got = reinterpret_cast<ElfW(Addr)**>(load_bias + d->d_un.d_ptr);
#endif
        // Ignore for other platforms... (because RTLD_LAZY is not supported)
        break;

      case DT_DEBUG:
        // Set the DT_DEBUG entry to the address of _r_debug for GDB
        // if the dynamic table is writable
// FIXME: not working currently for N64
// The flags for the LOAD and DYNAMIC program headers do not agree.
// The LOAD section containing the dynamic table has been mapped as
// read-only, but the DYNAMIC header claims it is writable.
//#if !(defined(__mips__) && defined(__LP64__))
//        if ((dynamic_flags & PF_W) != 0) {
//          d->d_un.d_val = reinterpret_cast<uintptr_t>(&_r_debug);
//        }
//        break;
//#endif
#if defined(USE_RELA)
      case DT_RELA:
        rela = reinterpret_cast<ElfW(Rela)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_RELASZ:
        rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
        break;

      case DT_RELAENT:
        if (d->d_un.d_val != sizeof(ElfW(Rela))) {
          LOGE("invalid DT_RELAENT: %zd", static_cast<size_t>(d->d_un.d_val));
          return false;
        }
        break;

      // ignored (see DT_RELCOUNT comments for details)
      case DT_RELACOUNT:
        break;

      case DT_REL:
        LOGE("unsupported DT_REL in \"%s\"", name);
        return false;

      case DT_RELSZ:
        LOGE("unsupported DT_RELSZ in \"%s\"", name);
        return false;
#else
      case DT_REL:
        rel = reinterpret_cast<ElfW(Rel)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_RELSZ:
        rel_count = d->d_un.d_val / sizeof(ElfW(Rel));
        break;

      case DT_RELENT:
        if (d->d_un.d_val != sizeof(ElfW(Rel))) {
          LOGE("invalid DT_RELENT: %zd", static_cast<size_t>(d->d_un.d_val));
          return false;
        }
        break;

      // "Indicates that all RELATIVE relocations have been concatenated together,
      // and specifies the RELATIVE relocation count."
      //
      // TODO: Spec also mentions that this can be used to optimize relocation process;
      // Not currently used by bionic linker - ignored.
      case DT_RELCOUNT:
        break;
      case DT_RELA:
        LOGE("unsupported DT_RELA in \"%s\"", name);
        return false;
#endif
      case DT_INIT:
        init_func = reinterpret_cast<linker_function_t>(load_bias + d->d_un.d_ptr);
        DL_DEBUG("%s constructors (DT_INIT) found at %p", name, init_func);
        break;

      case DT_FINI:
        fini_func = reinterpret_cast<linker_function_t>(load_bias + d->d_un.d_ptr);
        DL_DEBUG("%s destructors (DT_FINI) found at %p", name, fini_func);
        break;

      case DT_INIT_ARRAY:
        init_array = reinterpret_cast<linker_function_t*>(load_bias + d->d_un.d_ptr);
        DL_DEBUG("%s constructors (DT_INIT_ARRAY) found at %p", name, init_array);
        break;

      case DT_INIT_ARRAYSZ:
        init_array_count = ((unsigned)d->d_un.d_val) / sizeof(ElfW(Addr));
        break;

      case DT_FINI_ARRAY:
        fini_array = reinterpret_cast<linker_function_t*>(load_bias + d->d_un.d_ptr);
        DL_DEBUG("%s destructors (DT_FINI_ARRAY) found at %p", name, fini_array);
        break;

      case DT_FINI_ARRAYSZ:
        fini_array_count = ((unsigned)d->d_un.d_val) / sizeof(ElfW(Addr));
        break;

      case DT_PREINIT_ARRAY:
        preinit_array = reinterpret_cast<linker_function_t*>(load_bias + d->d_un.d_ptr);
        DL_DEBUG("%s constructors (DT_PREINIT_ARRAY) found at %p", name, preinit_array);
        break;

      case DT_PREINIT_ARRAYSZ:
        preinit_array_count = ((unsigned)d->d_un.d_val) / sizeof(ElfW(Addr));
        break;

      case DT_TEXTREL:
#if defined(__LP64__)
        LOGE("text relocations (DT_TEXTREL) found in 64-bit ELF file \"%s\"", name);
        return false;
#else
        has_text_relocations = true;
        break;
#endif

      case DT_SYMBOLIC:
        has_DT_SYMBOLIC = true;
        break;

      case DT_NEEDED:
        ++needed_count;
        break;

      case DT_FLAGS:
        if (d->d_un.d_val & DF_TEXTREL) {
#if defined(__LP64__)
          LOGE("text relocations (DF_TEXTREL) found in 64-bit ELF file \"%s\"", name);
          return false;
#else
          has_text_relocations = true;
#endif
        }
        if (d->d_un.d_val & DF_SYMBOLIC) {
          has_DT_SYMBOLIC = true;
        }
        break;

      case DT_FLAGS_1:
        if ((d->d_un.d_val & DF_1_GLOBAL) != 0) {
          rtld_flags |= RTLD_GLOBAL;
        }
        // TODO: Implement other flags

        if ((d->d_un.d_val & ~(DF_1_NOW | DF_1_GLOBAL)) != 0) {
          DL_WARN("Unsupported flags DT_FLAGS_1=%p", reinterpret_cast<void*>(d->d_un.d_val));
        }
        break;
#if defined(__mips__)
      case DT_MIPS_RLD_MAP:
        // Set the DT_MIPS_RLD_MAP entry to the address of _r_debug for GDB.
        {
          r_debug** dp = reinterpret_cast<r_debug**>(load_bias + d->d_un.d_ptr);
          *dp = &_r_debug;
        }
        break;

      case DT_MIPS_RLD_VERSION:
      case DT_MIPS_FLAGS:
      case DT_MIPS_BASE_ADDRESS:
      case DT_MIPS_UNREFEXTNO:
        break;

      case DT_MIPS_SYMTABNO:
        mips_symtabno = d->d_un.d_val;
        break;

      case DT_MIPS_LOCAL_GOTNO:
        mips_local_gotno = d->d_un.d_val;
        break;

      case DT_MIPS_GOTSYM:
        mips_gotsym = d->d_un.d_val;
        break;
#endif
      // Ignored: "Its use has been superseded by the DF_BIND_NOW flag"
      case DT_BIND_NOW:
        break;

      // Ignore: bionic does not support symbol versioning...
      case DT_VERSYM:
      case DT_VERDEF:
      case DT_VERDEFNUM:
        break;

      default:
        if (!relocating_linker) {
//          DL_WARN("%s: unused DT entry: type %p arg %p", name,
//              reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
        }
        break;
    }
  }

  DEBUG("si->base = %p, si->strtab = %p, si->symtab = %p",
        reinterpret_cast<void*>(base), strtab, symtab);

  // Sanity checks.
  if (relocating_linker && needed_count != 0) {
    LOGE("linker cannot have DT_NEEDED dependencies on other libraries");
    return false;
  }
  if (nbucket == 0) {
    LOGE("empty/missing DT_HASH in \"%s\" (built with --hash-style=gnu?)", name);
    return false;
  }

  if (nbucket == 0 && gnu_nbucket_ == 0) {
    LOGE("empty/missing DT_HASH/DT_GNU_HASH in \"%s\" "
        "(new hash type from the future?)", name);
    return false;
  }

  if (strtab == 0) {
    LOGE("empty/missing DT_STRTAB in \"%s\"", name);
    return false;
  }
  if (symtab == 0) {
    LOGE("empty/missing DT_SYMTAB in \"%s\"", name);
    return false;
  }
  return true;
}

bool soinfo::LinkImage() {

#if !defined(__LP64__)
  if (has_text_relocations) {
    // Make segments writable to allow text relocations to work properly. We will later call
    // phdr_table_protect_segments() after all of them are applied and all constructors are run.
//    DL_WARN("%s has text relocations. This is wasting memory and prevents "
//            "security hardening. Please fix.", name);
    if (phdr_table_unprotect_segments(phdr, phnum, load_bias) < 0) {
//      LOGE("can't unprotect loadable segments for \"%s\": %s",
//             name, strerror(errno));
      return false;
    }
  }
#endif

#if defined(USE_RELA)
  if (rela != nullptr) {
    DL_DEBUG("[ relocating %s ]", name);
    if (Relocate(rela, rela_count)) {
      return false;
    }
  }
  if (plt_rela != nullptr) {
    DL_DEBUG("[ relocating %s plt ]", name);
    if (Relocate(plt_rela, plt_rela_count)) {
      return false;
    }
  }
#else
  if (rel != nullptr) {
    DL_DEBUG("[ relocating %s ]", name);
    if (Relocate(rel, rel_count)) {
      return false;
    }
  }
  if (plt_rel != nullptr) {
    DL_DEBUG("[ relocating %s plt ]", name);
    if (Relocate(plt_rel, plt_rel_count)) {
      return false;
    }
  }
#endif

#if defined(__mips__)
  if (!mips_relocate_got(this)) {
    return false;
  }
#endif

  DL_DEBUG("[ finished linking %s ]", name);

#if !defined(__LP64__)
  if (has_text_relocations) {
    // All relocations are done, we can protect our segments back to read-only.
    if (phdr_table_protect_segments(phdr, phnum, load_bias) < 0) {
      LOGE("can't protect segments for \"%s\": %s",
             name, strerror(errno));
      return false;
    }
  }
#endif

  /* We can also turn on GNU RELRO protection */
  if (phdr_table_protect_gnu_relro(phdr, phnum, load_bias) < 0) {
    LOGE("can't enable GNU RELRO protection for \"%s\": %s",
           name, strerror(errno));
    return false;
  }

  return true;
}

/*
 * This is linker soinfo for GDB. See details below.
 */
#if defined(__LP64__)
#define LINKER_PATH "/system/bin/linker64"
#else
#define LINKER_PATH "/system/bin/linker"
#endif
static soinfo linker_soinfo_for_gdb(LINKER_PATH, nullptr, 0);

/* gdb expects the linker to be in the debug shared object list.
 * Without this, gdb has trouble locating the linker's ".text"
 * and ".plt" sections. Gdb could also potentially use this to
 * relocate the offset of our exported 'rtld_db_dlactivity' symbol.
 * Don't use soinfo_alloc(), because the linker shouldn't
 * be on the soinfo list.
 */
static void init_linker_info_for_gdb(ElfW(Addr) linker_base) {
  linker_soinfo_for_gdb.base = linker_base;

  /*
   * Set the dynamic field in the link map otherwise gdb will complain with
   * the following:
   *   warning: .dynamic section for "/system/bin/linker" is not at the
   *   expected address (wrong library or version mismatch?)
   */
  ElfW(Ehdr)* elf_hdr = reinterpret_cast<ElfW(Ehdr)*>(linker_base);
  ElfW(Phdr)* phdr = reinterpret_cast<ElfW(Phdr)*>(linker_base + elf_hdr->e_phoff);
  phdr_table_get_dynamic_section(phdr, elf_hdr->e_phnum, linker_base,
                                 &linker_soinfo_for_gdb.dynamic, nullptr);
//  insert_soinfo_into_debug_map(&linker_soinfo_for_gdb);
}

/* Compute the load-bias of an existing executable. This shall only
 * be used to compute the load bias of an executable or shared library
 * that was loaded by the kernel itself.
 *
 * Input:
 *    elf    -> address of ELF header, assumed to be at the start of the file.
 * Return:
 *    load bias, i.e. add the value of any p_vaddr in the file to get
 *    the corresponding address in memory.
 */
static ElfW(Addr) get_elf_exec_load_bias(const ElfW(Ehdr)* elf) {
  ElfW(Addr) offset = elf->e_phoff;
  const ElfW(Phdr)* phdr_table = reinterpret_cast<const ElfW(Phdr)*>(reinterpret_cast<uintptr_t>(elf) + offset);
  const ElfW(Phdr)* phdr_end = phdr_table + elf->e_phnum;

  for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_end; phdr++) {
    if (phdr->p_type == PT_LOAD) {
      return reinterpret_cast<ElfW(Addr)>(elf) + phdr->p_offset - phdr->p_vaddr;
    }
  }
  return 0;
}

extern "C" void _start();

int linker_pre_alloc(size_t size, uint32_t min, uint32_t max, const char* sopath) {
    if (min + size > max) {
        max = min + size;
    }
    if (min > 0) {
        min = 0;
    }

    ElfW(Addr) min_vaddr = PAGE_START(min);
    ElfW(Addr) max_vaddr = PAGE_END(max);

    size_t load_size_ = max_vaddr - min_vaddr;
    uint8_t* addr = reinterpret_cast<uint8_t*>(min_vaddr);
    void* start;

    size_t reserved_size = 0;
    bool reserved_hint = true;

    int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
    start = mmap(addr - PAGE_SIZE, load_size_ + PAGE_SIZE, PROT_WRITE | PROT_READ | PROT_EXEC, mmap_flags, -1, 0);
    if (start == MAP_FAILED) {
      LOGD("couldn't reserve %zd bytes of address space, errono : %s", load_size_, strerror(errno));
      return -1;
    }
    start = reinterpret_cast<void*>(start + PAGE_SIZE);

    char soname[1024];
    char dir[1024];
    sprintf(dir, "%s/%x_%x_pseudo", sopath, start, reinterpret_cast<ElfW(Addr)>(start) + load_size_);
    sprintf(soname, "%s/libname.so", dir);
    mkdir(dir, S_IRWXU);

    int holder_fd = open(soname, O_RDWR | O_CREAT);
    if (holder_fd > 0) {
        if (write(holder_fd, soname, 1024) == 1024) {
            mmap(start - PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, holder_fd, 0);
        }
        close(holder_fd);
    } else {
        DEBUG("create %s failed!" , soname);
    }

    g_merge->start = start;
    g_merge->bias = reinterpret_cast<uint8_t*>(start) - addr;
    g_merge->load_size = load_size_;

    DEBUG("merge: %x, , pre_alloc start: %x, total : %x", g_merge, g_merge->start, g_merge->load_size);
    return 0;
}
