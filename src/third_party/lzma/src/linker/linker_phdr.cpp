/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include "linker_phdr.h"

#include <errno.h>
#include <machine/exec.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>

#include "linker.h"

#define mmap64 mmap

#include <android/log.h>
#define LOG_TAG    "testhook"
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG,__VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,__VA_ARGS__)
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG,__VA_ARGS__)

#define  DEBUG(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,__VA_ARGS__)

#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

ElfReader::ElfReader(const char* name, int fd, off64_t file_offset, void* pre_start, ElfW(Addr) pre_bias, uint32_t total)
    : name_(name), fd_(fd), file_offset_(file_offset),
      phdr_num_(0), phdr_mmap_(nullptr), phdr_table_(nullptr), phdr_size_(0),
      load_start_(nullptr), load_size_(0), load_bias_(0),
      loaded_phdr_(nullptr),
      m_pre_start(pre_start), m_pre_bias(pre_bias), m_pre_load_size(total) {
}

ElfReader::~ElfReader() {
  if (phdr_mmap_ != nullptr) {
    munmap(phdr_mmap_, phdr_size_);
  }

  if (m_pre_load_size > load_size_) {
      LOGE("total %d, load len %d", m_pre_load_size, load_size_);
      munmap(reinterpret_cast<void*>(reinterpret_cast<size_t>(m_pre_start) + load_size_), (m_pre_load_size - load_size_));

  }
}

bool ElfReader::Load() {
  return ReadElfHeader() &&
         VerifyElfHeader() &&
         ReadProgramHeader() &&
         ReserveAddressSpace() &&
         LoadSegments() &&
         FindPhdr();
}

bool ElfReader::ReadElfHeader() {
    if (fd_ == -1) {
        header_ = *static_cast<ElfW(Ehdr)*>(m_pre_start);
        return true;
    } else {
        ssize_t rc = TEMP_FAILURE_RETRY(pread(fd_, &header_, sizeof(header_), file_offset_));
        if (rc < 0) {
            LOGE("can't read file \"%s\": %s", name_, strerror(errno));
            return false;
        }

        if (rc != sizeof(header_)) {
            LOGE("\"%s\" is too small to be an ELF executable: only found %zd bytes", name_,
                    static_cast<size_t>(rc));
            return false;
        }
        return true;
    }
}

bool ElfReader::VerifyElfHeader() {
  if (memcmp(header_.e_ident, ELFMAG, SELFMAG) != 0) {
      LOGE("\"%s\" has bad ELF magic", name_);
      return false;
  }

  // Try to give a clear diagnostic for ELF class mismatches, since they're
  // an easy mistake to make during the 32-bit/64-bit transition period.
  int elf_class = header_.e_ident[EI_CLASS];
#if defined(__LP64__)
  if (elf_class != ELFCLASS64) {
    if (elf_class == ELFCLASS32) {
        LOGE("\"%s\" is 32-bit instead of 64-bit", name_);
    } else {
        LOGE("\"%s\" has unknown ELF class: %d", name_, elf_class);
    }
    return false;
  }
#else
  if (elf_class != ELFCLASS32) {
    if (elf_class == ELFCLASS64) {
        LOGE("\"%s\" is 64-bit instead of 32-bit", name_);
    } else {
        LOGE("\"%s\" has unknown ELF class: %d", name_, elf_class);
    }
    return false;
  }
#endif

  if (header_.e_ident[EI_DATA] != ELFDATA2LSB) {
      LOGE("\"%s\" not little-endian: %d", name_, header_.e_ident[EI_DATA]);
      return false;
  }

  if (header_.e_type != ET_DYN) {
      LOGE("\"%s\" has unexpected e_type: %d", name_, header_.e_type);
      return false;
  }

  if (header_.e_version != EV_CURRENT) {
      LOGE("\"%s\" has unexpected e_version: %d", name_, header_.e_version);
      return false;
  }

  if (header_.e_machine != ELF_TARG_MACH) {
      LOGE("\"%s\" has unexpected e_machine: %d", name_, header_.e_machine);
      return false;
  }

  return true;
}

// Loads the program header table from an ELF file into a read-only private
// anonymous mmap-ed block.
bool ElfReader::ReadProgramHeader() {
  phdr_num_ = header_.e_phnum;

  // Like the kernel, we only accept program header tables that
  // are smaller than 64KiB.
  if (phdr_num_ < 1 || phdr_num_ > 65536/sizeof(ElfW(Phdr))) {
      LOGE("\"%s\" has invalid e_phnum: %zd", name_, phdr_num_);
      return false;
  }

  ElfW(Addr) page_min = PAGE_START(header_.e_phoff);
  ElfW(Addr) page_max = PAGE_END(header_.e_phoff + (phdr_num_ * sizeof(ElfW(Phdr))));
  ElfW(Addr) page_offset = PAGE_OFFSET(header_.e_phoff);

  phdr_size_ = page_max - page_min;

  void* mmap_result = nullptr;
  if(fd_ == -1) {
      phdr_table_ = reinterpret_cast<ElfW(Phdr)*>(reinterpret_cast<char*>(m_pre_start) + page_offset);
      DEBUG("header : num : %d, off : %d", header_.e_phnum, header_.e_phoff);
      return true;
  } else {
      mmap_result = mmap64(nullptr, phdr_size_, PROT_READ, MAP_PRIVATE, fd_, file_offset_ + page_min);
      if (mmap_result == MAP_FAILED) {
          LOGE("\"%s\" phdr mmap failed: %s", name_, strerror(errno));
          return false;
      }

      phdr_mmap_ = mmap_result;
      phdr_table_ = reinterpret_cast<ElfW(Phdr)*>(reinterpret_cast<char*>(mmap_result) + page_offset);
      return true;
  }
}

/* Returns the size of the extent of all the possibly non-contiguous
 * loadable segments in an ELF program header table. This corresponds
 * to the page-aligned size in bytes that needs to be reserved in the
 * process' address space. If there are no loadable segments, 0 is
 * returned.
 *
 * If out_min_vaddr or out_max_vaddr are not null, they will be
 * set to the minimum and maximum addresses of pages to be reserved,
 * or 0 if there is nothing to load.
 */
#define UINT32_MAX    (4294967295U)
size_t phdr_table_get_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                ElfW(Addr)* out_min_vaddr,
                                ElfW(Addr)* out_max_vaddr) {
  ElfW(Addr) min_vaddr = UINT32_MAX;//UINTPTR_MAX;
  ElfW(Addr) max_vaddr = 0;

  bool found_pt_load = false;
  for (size_t i = 0; i < phdr_count; ++i) {
    const ElfW(Phdr)* phdr = &phdr_table[i];

    if (phdr->p_type != PT_LOAD) {
      continue;
    }
    found_pt_load = true;

    if (phdr->p_vaddr < min_vaddr) {
      min_vaddr = phdr->p_vaddr;
    }

    if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) {
      max_vaddr = phdr->p_vaddr + phdr->p_memsz;
    }
  }
  if (!found_pt_load) {
    min_vaddr = 0;
  }

  min_vaddr = PAGE_START(min_vaddr);
  max_vaddr = PAGE_END(max_vaddr);

  if (out_min_vaddr != nullptr) {
    *out_min_vaddr = min_vaddr;
  }
  if (out_max_vaddr != nullptr) {
    *out_max_vaddr = max_vaddr;
  }
  return max_vaddr - min_vaddr;
}

// Reserve a virtual address range big enough to hold all loadable
// segments of a program header table. This is done by creating a
// private anonymous mmap() with PROT_NONE.
bool ElfReader::ReserveAddressSpace() {
  ElfW(Addr) min_vaddr;
  load_size_ = phdr_table_get_load_size(phdr_table_, phdr_num_, &min_vaddr);
  if (load_size_ == 0) {
      LOGE("\"%s\" has no loadable segments", name_);
      return false;
  }

  DEBUG("loaded size:%d", load_size_);

  load_start_ = m_pre_start;
  load_bias_ = m_pre_bias;
  return true;
}

bool ElfReader::LoadSegments() {
  ElfW(Addr) file_page_end = 0;
  for (size_t i = 0; i < phdr_num_; ++i) {
    const ElfW(Phdr)* phdr = &phdr_table_[i];

    if (phdr->p_type != PT_LOAD) {
      continue;
    }

    // Segment addresses in memory.
    ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
    ElfW(Addr) seg_end   = seg_start + phdr->p_memsz;

    ElfW(Addr) seg_page_start = PAGE_START(seg_start);
    ElfW(Addr) seg_page_end   = PAGE_END(seg_end);

    ElfW(Addr) seg_file_end   = seg_start + phdr->p_filesz;

    // File offsets.
    ElfW(Addr) file_start = phdr->p_offset;
    ElfW(Addr) file_end   = file_start + phdr->p_filesz;

    ElfW(Addr) file_page_start = PAGE_START(file_start);
    ElfW(Addr) file_length = file_end - file_page_start;

    if (file_length != 0) {
        void* seg_addr = nullptr;
        if (fd_ != -1) {
            seg_addr = mmap64(reinterpret_cast<void*>(seg_page_start),
                            file_length,
                            PFLAGS_TO_PROT(phdr->p_flags),
                            MAP_FIXED|MAP_PRIVATE,
                            fd_,
                            file_offset_ + file_page_start);

            if (seg_addr == MAP_FAILED) {
                LOGE("couldn't map \"%s\" segment %zd: %s", name_, i, strerror(errno));
                return false;
            }
        } else {
            if (phdr->p_vaddr == 0  && (phdr->p_flags & PF_W) == 0) {
                m_text_size = file_length;

                file_page_end = PAGE_START(file_end);
                void* left = mmap(nullptr,
                        m_pre_load_size - file_page_end,
                        PROT_WRITE | PROT_READ | PROT_EXEC,
                        MAP_ANONYMOUS|MAP_PRIVATE,
                        -1,
                        0);
                memcpy(left, reinterpret_cast<void*>(reinterpret_cast<ElfW(Addr)>(m_pre_start) + file_page_end), m_pre_load_size - file_page_end);
                m_other_start = reinterpret_cast<ElfW(Addr)>(left);

                // fill fake so elf header
                memcpy(load_start_ - PAGE_SIZE, load_start_, PAGE_SIZE);

                DEBUG("first LOAD segments : p_vaddr=%x, file_page_end=%x, left=%x, len=%d", phdr->p_vaddr,
                        file_page_end, left, m_pre_load_size - file_page_end);
                if (msync(load_start_ - PAGE_SIZE, PAGE_SIZE, MS_SYNC) == -1) {
                    return false;
                }
            } else {
                DEBUG("next LOAD segments : file_page_start=%x, file_page_end=%x, seg_page_start=%x, file_length=%d", file_page_start ,file_page_end,
                        seg_page_start ,file_length);
                ElfW(Addr) diffs = (file_page_start == file_page_end) ? 0 : file_page_start - file_page_end;
                memcpy(reinterpret_cast<void*>(seg_page_start), reinterpret_cast<void*>(m_other_start + diffs), file_length);
            }
        }
    }

    // if the segment is writable, and does not end on a page boundary,
    // zero-fill it until the page limit.
    if ((phdr->p_flags & PF_W) != 0 && PAGE_OFFSET(seg_file_end) > 0) {
      memset(reinterpret_cast<void*>(seg_file_end), 0, PAGE_SIZE - PAGE_OFFSET(seg_file_end));
    }

    seg_file_end = PAGE_END(seg_file_end);

    // seg_file_end is now the first page address after the file
    // content. If seg_end is larger, we need to zero anything
    // between them. This is done by using a private anonymous
    // map for all extra pages.
    if (seg_page_end > seg_file_end) {
      void* zeromap = mmap(reinterpret_cast<void*>(seg_file_end),
                           seg_page_end - seg_file_end,
                           PFLAGS_TO_PROT(phdr->p_flags),
                           MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,
                           -1,
                           0);
      if (zeromap == MAP_FAILED) {
          LOGE("couldn't zero fill \"%s\" gap: %s", name_, strerror(errno));
          return false;
      }
    }
  }

  return true;
}

/* Used internally. Used to set the protection bits of all loaded segments
 * with optional extra flags (i.e. really PROT_WRITE). Used by
 * phdr_table_protect_segments and phdr_table_unprotect_segments.
 */
static int _phdr_table_set_load_prot(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                     ElfW(Addr) load_bias, int extra_prot_flags) {
  const ElfW(Phdr)* phdr = phdr_table;
  const ElfW(Phdr)* phdr_limit = phdr + phdr_count;

  for (; phdr < phdr_limit; phdr++) {
    if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_W) != 0) {
      continue;
    }

    ElfW(Addr) seg_page_start = PAGE_START(phdr->p_vaddr) + load_bias;
    ElfW(Addr) seg_page_end   = PAGE_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;

    int ret = mprotect(reinterpret_cast<void*>(seg_page_start),
                       seg_page_end - seg_page_start,
                       PFLAGS_TO_PROT(phdr->p_flags) | extra_prot_flags);
    if (ret < 0) {
      return -1;
    }
  }
  return 0;
}

/* Restore the original protection modes for all loadable segments.
 * You should only call this after phdr_table_unprotect_segments and
 * applying all relocations.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Return:
 *   0 on error, -1 on failure (error code in errno).
 */
int phdr_table_protect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias) {
  return _phdr_table_set_load_prot(phdr_table, phdr_count, load_bias, 0);
}

/* Change the protection of all loaded segments in memory to writable.
 * This is useful before performing relocations. Once completed, you
 * will have to call phdr_table_protect_segments to restore the original
 * protection flags on all segments.
 *
 * Note that some writable segments can also have their content turned
 * to read-only by calling phdr_table_protect_gnu_relro. This is no
 * performed here.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Return:
 *   0 on error, -1 on failure (error code in errno).
 */
int phdr_table_unprotect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias) {
  return _phdr_table_set_load_prot(phdr_table, phdr_count, load_bias, PROT_WRITE);
}

#define PT_GNU_RELRO 0x6474e552
/* Used internally by phdr_table_protect_gnu_relro and
 * phdr_table_unprotect_gnu_relro.
 */
static int _phdr_table_set_gnu_relro_prot(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                          ElfW(Addr) load_bias, int prot_flags) {
  const ElfW(Phdr)* phdr = phdr_table;
  const ElfW(Phdr)* phdr_limit = phdr + phdr_count;

  for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
    if (phdr->p_type != PT_GNU_RELRO) {
      continue;
    }

    // Tricky: what happens when the relro segment does not start
    // or end at page boundaries? We're going to be over-protective
    // here and put every page touched by the segment as read-only.

    // This seems to match Ian Lance Taylor's description of the
    // feature at http://www.airs.com/blog/archives/189.

    //    Extract:
    //       Note that the current dynamic linker code will only work
    //       correctly if the PT_GNU_RELRO segment starts on a page
    //       boundary. This is because the dynamic linker rounds the
    //       p_vaddr field down to the previous page boundary. If
    //       there is anything on the page which should not be read-only,
    //       the program is likely to fail at runtime. So in effect the
    //       linker must only emit a PT_GNU_RELRO segment if it ensures
    //       that it starts on a page boundary.
    ElfW(Addr) seg_page_start = PAGE_START(phdr->p_vaddr) + load_bias;
    ElfW(Addr) seg_page_end   = PAGE_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;

    int ret = mprotect(reinterpret_cast<void*>(seg_page_start),
                       seg_page_end - seg_page_start,
                       prot_flags);
    if (ret < 0) {
      return -1;
    }
  }
  return 0;
}

/* Apply GNU relro protection if specified by the program header. This will
 * turn some of the pages of a writable PT_LOAD segment to read-only, as
 * specified by one or more PT_GNU_RELRO segments. This must be always
 * performed after relocations.
 *
 * The areas typically covered are .got and .data.rel.ro, these are
 * read-only from the program's POV, but contain absolute addresses
 * that need to be relocated before use.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Return:
 *   0 on error, -1 on failure (error code in errno).
 */
int phdr_table_protect_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias) {
  return _phdr_table_set_gnu_relro_prot(phdr_table, phdr_count, load_bias, PROT_READ);
}
#if defined(__arm__)

#  ifndef PT_ARM_EXIDX
#    define PT_ARM_EXIDX    0x70000001      /* .ARM.exidx segment */
#  endif

/* Return the address and size of the .ARM.exidx section in memory,
 * if present.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Output:
 *   arm_exidx       -> address of table in memory (null on failure).
 *   arm_exidx_count -> number of items in table (0 on failure).
 * Return:
 *   0 on error, -1 on failure (_no_ error code in errno)
 */
int phdr_table_get_arm_exidx(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                             ElfW(Addr) load_bias,
                             ElfW(Addr)** arm_exidx, unsigned* arm_exidx_count) {
  const ElfW(Phdr)* phdr = phdr_table;
  const ElfW(Phdr)* phdr_limit = phdr + phdr_count;

  for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
    if (phdr->p_type != PT_ARM_EXIDX) {
      continue;
    }

    *arm_exidx = reinterpret_cast<ElfW(Addr)*>(load_bias + phdr->p_vaddr);
    *arm_exidx_count = (unsigned)(phdr->p_memsz / 8);
    return 0;
  }
  *arm_exidx = nullptr;
  *arm_exidx_count = 0;
  return -1;
}
#endif

/* Return the address and size of the ELF file's .dynamic section in memory,
 * or null if missing.
 *
 * Input:
 *   phdr_table  -> program header table
 *   phdr_count  -> number of entries in tables
 *   load_bias   -> load bias
 * Output:
 *   dynamic       -> address of table in memory (null on failure).
 *   dynamic_flags -> protection flags for section (unset on failure)
 * Return:
 *   void
 */
void phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                    ElfW(Addr) load_bias, ElfW(Dyn)** dynamic,
                                    ElfW(Word)* dynamic_flags) {
  *dynamic = nullptr;
  for (const ElfW(Phdr)* phdr = phdr_table, *phdr_limit = phdr + phdr_count; phdr < phdr_limit; phdr++) {
    if (phdr->p_type == PT_DYNAMIC) {
      *dynamic = reinterpret_cast<ElfW(Dyn)*>(load_bias + phdr->p_vaddr);
      if (dynamic_flags) {
        *dynamic_flags = phdr->p_flags;
      }
      return;
    }
  }
}

// Returns the address of the program header table as it appears in the loaded
// segments in memory. This is in contrast with 'phdr_table_' which
// is temporary and will be released before the library is relocated.
bool ElfReader::FindPhdr() {
  const ElfW(Phdr)* phdr_limit = phdr_table_ + phdr_num_;

  // If there is a PT_PHDR, use it directly.
  for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
    if (phdr->p_type == PT_PHDR) {
      return CheckPhdr(load_bias_ + phdr->p_vaddr);
    }
  }

  // Otherwise, check the first loadable segment. If its file offset
  // is 0, it starts with the ELF header, and we can trivially find the
  // loaded program header from it.
  for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
    if (phdr->p_type == PT_LOAD) {
      if (phdr->p_offset == 0) {
        ElfW(Addr)  elf_addr = load_bias_ + phdr->p_vaddr;
        const ElfW(Ehdr)* ehdr = reinterpret_cast<const ElfW(Ehdr)*>(elf_addr);
        ElfW(Addr)  offset = ehdr->e_phoff;
        return CheckPhdr((ElfW(Addr))ehdr + offset);
      }
      break;
    }
  }

    LOGE("can't find loaded phdr for \"%s\"", name_);
    return false;
}

// Ensures that our program header is actually within a loadable
// segment. This should help catch badly-formed ELF files that
// would cause the linker to crash later when trying to access it.
bool ElfReader::CheckPhdr(ElfW(Addr) loaded) {
  const ElfW(Phdr)* phdr_limit = phdr_table_ + phdr_num_;
  ElfW(Addr) loaded_end = loaded + (phdr_num_ * sizeof(ElfW(Phdr)));
  for (ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
    if (phdr->p_type != PT_LOAD) {
      continue;
    }
    ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
    ElfW(Addr) seg_end = phdr->p_filesz + seg_start;
    if (seg_start <= loaded && loaded_end <= seg_end) {
      loaded_phdr_ = reinterpret_cast<const ElfW(Phdr)*>(loaded);
      return true;
    }
  }
    LOGE("\"%s\" loaded phdr %p not in loadable segment", name_, reinterpret_cast<void*>(loaded));
    return false;
}
