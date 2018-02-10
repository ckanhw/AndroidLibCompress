/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef _LINKER_H_
#define _LINKER_H_

#include <elf.h>
#include <machine/elf_machdep.h>
#include <inttypes.h>

#include <link.h>
#include "../7zMain.h"

#include <unistd.h>
//#include <android/dlext.h>
#include <sys/stat.h>

//#include "private/libc_logging.h"
#include "linked_list.h"

#include "elf_common.h"

#if defined(__LP64__)
#define ELFW(what) ELF64_ ## what
#else
#define ELFW(what) ELF32_ ## what
#endif

// mips64 interprets Elf64_Rel structures' r_info field differently.
// bionic (like other C libraries) has macros that assume regular ELF files,
// but the dynamic linker needs to be able to load mips64 ELF files.
#if defined(__mips__) && defined(__LP64__)
#undef ELF64_R_SYM
#undef ELF64_R_TYPE
#undef ELF64_R_INFO
#define ELF64_R_SYM(info)   (((info) >> 0) & 0xffffffff)
#define ELF64_R_SSYM(info)  (((info) >> 32) & 0xff)
#define ELF64_R_TYPE3(info) (((info) >> 40) & 0xff)
#define ELF64_R_TYPE2(info) (((info) >> 48) & 0xff)
#define ELF64_R_TYPE(info)  (((info) >> 56) & 0xff)
#endif

// Returns the address of the page containing address 'x'.
#define PAGE_START(x)  ((x) & PAGE_MASK)

// Returns the offset of address 'x' in its page.
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)

// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))

#define FLAG_LINKED     0x00000001
#define FLAG_EXE        0x00000004 // The main executable
#define FLAG_LINKER     0x00000010 // The linker itself
#define FLAG_NEW_SOINFO 0x40000000 // new soinfo format

#define SOINFO_VERSION 0

#define SOINFO_NAME_LEN 128

typedef void (*linker_function_t)();

// Android uses RELA for aarch64 and x86_64. mips64 still uses REL.
#if defined(__aarch64__) || defined(__x86_64__)
#define USE_RELA 1
#endif

struct soinfo;

class SoinfoListAllocator {
public:
  static LinkedListEntry<soinfo>* alloc();
  static void free(LinkedListEntry<soinfo>* entry);
private:
  // unconstructable
//  DISALLOW_IMPLICIT_CONSTRUCTORS(SoinfoListAllocator);
};

struct soinfo {
 public:
  typedef LinkedList<soinfo, SoinfoListAllocator> soinfo_list_t;
 public:
  char name[SOINFO_NAME_LEN];
  const ElfW(Phdr)* phdr;
  size_t phnum;
  ElfW(Addr) entry;
  ElfW(Addr) base;
  size_t size;

#ifndef __LP64__
  uint32_t unused1;  // DO NOT USE, maintained for compatibility.
#endif

  ElfW(Dyn)* dynamic;

#ifndef __LP64__
  uint32_t unused2; // DO NOT USE, maintained for compatibility
  uint32_t unused3; // DO NOT USE, maintained for compatibility
#endif

  soinfo* next;
  unsigned flags;

 public:
  const char* strtab;
 public:
  ElfW(Sym)* symtab;

  size_t nbucket;
  size_t nchain;
  unsigned* bucket;
  unsigned* chain;

#if defined(__mips__) || !defined(__LP64__)
  // This is only used by mips and mips64, but needs to be here for
  // all 32-bit architectures to preserve binary compatibility.
  ElfW(Addr)** plt_got;
#endif

#if defined(USE_RELA)
  ElfW(Rela)* plt_rela;
  size_t plt_rela_count;

  ElfW(Rela)* rela;
  size_t rela_count;
#else
  ElfW(Rel)* plt_rel;
  size_t plt_rel_count;

  ElfW(Rel)* rel;
  size_t rel_count;
#endif

  linker_function_t* preinit_array;
  size_t preinit_array_count;

  linker_function_t* init_array;
  size_t init_array_count;
  linker_function_t* fini_array;
  size_t fini_array_count;

  linker_function_t init_func;
  linker_function_t fini_func;

#if defined(__arm__)
  // ARM EABI section used for stack unwinding.
  unsigned* ARM_exidx;
  size_t ARM_exidx_count;
#elif defined(__mips__)
  unsigned mips_symtabno;
  unsigned mips_local_gotno;
  unsigned mips_gotsym;
#endif

  size_t ref_count;

  struct link_map {
    ElfW(Addr) l_addr;
    char* l_name;
    ElfW(Dyn)* l_ld;
    struct link_map* l_next;
    struct link_map* l_prev;
  };

  link_map link_map_head;

  bool constructors_called;

  // When you read a virtual address from the ELF file, add this
  // value to get the corresponding address in the process' address space.
  ElfW(Addr) load_bias;

#if !defined(__LP64__)
  bool has_text_relocations;
#endif
  bool has_DT_SYMBOLIC;

  soinfo(const char* name, const struct stat* file_stat, off64_t file_offset);

  void CallConstructors();
  void CallDestructors();
  void CallPreInitConstructors();
  bool PrelinkImage();
  bool LinkImage();

  void add_child(soinfo* child);
  void remove_all_links();

  ino_t get_st_ino();
  dev_t get_st_dev();
  off64_t get_file_offset();

  soinfo_list_t& get_children();
  soinfo_list_t& get_parents();

  ElfW(Addr) resolve_symbol_address(ElfW(Sym)* s);

  const char* get_string(ElfW(Word) index) const;

  bool inline has_min_version(uint32_t min_version) const {
    return (flags & FLAG_NEW_SOINFO) != 0 && version >= min_version;
  }

  ElfW(Sym)* gnu_lookup(unsigned hash, const char* name);

 private:
  void CallArray(const char* array_name, linker_function_t* functions, size_t count, bool reverse);
  void CallFunction(const char* function_name, linker_function_t function);
#if defined(USE_RELA)
  int Relocate(ElfW(Rela)* rela, unsigned count);
#else
  int Relocate(ElfW(Rel)* rel, unsigned count);
#endif

 private:
  // This part of the structure is only available
  // when FLAG_NEW_SOINFO is set in this->flags.
  uint32_t version;

  // version >= 0
  dev_t st_dev;
  ino_t st_ino;

  // dependency graph
  soinfo_list_t children;
  soinfo_list_t parents;

  // version >= 1
  off64_t file_offset;
  uint32_t rtld_flags;
  uint32_t dt_flags_1_;

  size_t strtab_size;

  size_t gnu_nbucket_;
  uint32_t* gnu_bucket_;
  uint32_t* gnu_chain_;
  uint32_t gnu_maskwords_;
  uint32_t gnu_shift2_;
  ElfW(Addr)* gnu_bloom_filter_;

  friend soinfo* get_libdl_info();
};

extern soinfo* get_libdl_info();

void do_android_get_LD_LIBRARY_PATH(char*, size_t);
void do_android_update_LD_LIBRARY_PATH(const char* ld_library_path);
soinfo* do_dlopen(const char* name, int flags);
void do_dlclose(soinfo* si);

ElfW(Sym)* dlsym_linear_lookup(const char* name, soinfo** found, soinfo* start);
soinfo* find_containing_library(const void* addr);

ElfW(Sym)* dladdr_find_symbol(soinfo* si, const void* addr);

void* dlsym_handle_lookup(soinfo* si, soinfo** found, const char* name);

int linker_pre_alloc(size_t size, uint32_t min, uint32_t max, const char* path);

_Unwind_Ptr my_dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount, soinfo* si);
#endif
