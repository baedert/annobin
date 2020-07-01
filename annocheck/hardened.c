/* Checks the hardened status of the given file.
   Copyright (c) 2018 - 2020 Red Hat.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  You should have received a copy of the GNU General Public
  License along with this program; see the file COPYING3. If not,
  see <http://www.gnu.org/licenses/>.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "annobin-global.h"
#include "annocheck.h"

typedef struct hardened_note_data
{
  ulong         start;
  ulong         end;
} hardened_note_data;

/* Set by the constructor.  */
static bool disabled = false;

/* Can be changed by a command line option.  */
static bool ignore_gaps = false;

enum tool
{
  TOOL_UNKNOWN = 0,
  TOOL_MIXED,
  TOOL_GCC,
  TOOL_GAS,
  TOOL_CLANG,
  TOOL_LLVM,
  TOOL_FORTRAN,
  TOOL_GO,
  TOOL_RUST
};
  
/* The contents of this structure are used on a per-input-file basis.
   The fields are initialised by start().  */
static struct per_file
{
  Elf64_Half  e_type;
  Elf64_Half  e_machine;
  Elf64_Addr  e_entry;
  ulong       text_section_name_index;
  ulong       text_section_alignment;
  bool        is_little_endian;
  bool        debuginfo_file;
  bool        compiled_code_seen;
  bool        build_notes_seen;
  int         num_fails;
  int         num_maybes;
  unsigned    anno_major;
  unsigned    anno_minor;
  unsigned    anno_rel;
  unsigned    run_major;
  unsigned    run_minor;
  unsigned    run_rel;

  enum tool   tool;
  uint        version;
  
  bool        warned_producer;
  bool        warned_about_instrumentation;
  bool        warned_version_mismatch;
  bool        warned_command_line;
} per_file;

static hardened_note_data *  ranges = NULL;
static unsigned              num_allocated_ranges = 0;
static unsigned              next_free_range = 0;
#define RANGE_ALLOC_DELTA    16

/* Array used to store instruction bytes at entry point.
   Use for verbose reporting when the ENTRY test fails.  */
static unsigned char entry_bytes[4];

/* This structure defines an individual test.  */

typedef struct test
{
  bool	            enabled;	  /* If false then do not run this test.  */
  unsigned int      num_pass;
  unsigned int      num_fail;
  unsigned int      num_maybe;
  const char *      name;	  /* Also used as part of the command line option to disable the test.  */
  const char *      description;  /* Used in the --help output to describe the test.  */
  void (*           show_result)(annocheck_data *, struct test *);
} test;

enum test_index
{
  TEST_BIND_NOW,
  TEST_BRANCH_PROTECTION,
  TEST_CF_PROTECTION,
  TEST_DYNAMIC,
  TEST_ENTRY,
  TEST_FORTIFY,
  TEST_GLIBCXX_ASSERTIONS,
  TEST_GNU_RELRO,
  TEST_GNU_STACK,
  TEST_OPTIMIZATION,
  TEST_PIC,
  TEST_PIE,
  TEST_PROPERTY_NOTE,
  TEST_RUN_PATH,
  TEST_RWX_SEG,
  TEST_SHORT_ENUM,
  TEST_STACK_CLASH,
  TEST_STACK_PROT,
  TEST_STACK_REALIGN,
  TEST_TEXTREL,
  TEST_THREADS,
  TEST_WARNINGS,
  TEST_WRITEABLE_GOT,

  TEST_MAX
};

static void show_BIND_NOW           (annocheck_data *, test *);
static void show_BRANCH_PROTECTION  (annocheck_data *, test *);
static void show_CF_PROTECTION      (annocheck_data *, test *);
static void show_DYNAMIC            (annocheck_data *, test *);
static void show_ENTRY              (annocheck_data *, test *);
static void show_FORTIFY            (annocheck_data *, test *);
static void show_GLIBCXX_ASSERTIONS (annocheck_data *, test *);
static void show_GNU_RELRO          (annocheck_data *, test *);
static void show_GNU_STACK          (annocheck_data *, test *);
static void show_OPTIMIZATION       (annocheck_data *, test *);
static void show_PIC                (annocheck_data *, test *);
static void show_PIE                (annocheck_data *, test *);
static void show_PROPERTY_NOTE      (annocheck_data *, test *);
static void show_RUN_PATH           (annocheck_data *, test *);
static void show_RWX_SEG            (annocheck_data *, test *);
static void show_SHORT_ENUM         (annocheck_data *, test *);
static void show_STACK_CLASH        (annocheck_data *, test *);
static void show_STACK_PROT         (annocheck_data *, test *);
static void show_STACK_REALIGN      (annocheck_data *, test *);
static void show_TEXTREL            (annocheck_data *, test *);
static void show_THREADS            (annocheck_data *, test *);
static void show_WARNINGS           (annocheck_data *, test *);
static void show_WRITEABLE_GOT      (annocheck_data *, test *);

#define TEST(name,upper,description) \
  [ TEST_##upper ] = { true, 0, 0, 0, #name, description, show_ ## upper }

/* Array of tests to run.  Default to enabling them all.
   The result field is initialised in the start() function.  */
static test tests [TEST_MAX] =
{
  TEST (bind-now,           BIND_NOW,           "Linked with -Wl,-z,now"),
  TEST (branch-protection,  BRANCH_PROTECTION,  "Compiled with -mbranch-protection=bti (AArch64 only, gcc 9+ only"),
  TEST (cf-protection,      CF_PROTECTION,      "Compiled with -fcf-protection=all (x86 only, gcc 8+ only)"),
  TEST (dynamic,            DYNAMIC,            "There is at most one dynamic segment/section"),
  TEST (entry,              ENTRY,              "The first instruction is ENDBR (x86 only)"),
  TEST (fortify,            FORTIFY,            "Compiled with -D_FORTIFY_SOURCE=2"),
  TEST (glibcxx-assertions, GLIBCXX_ASSERTIONS, "Compiled with -D_GLIBCXX_ASSERTIONS"),
  TEST (gnu-relro,          GNU_RELRO,          "The relocations for the GOT are not writeable"),
  TEST (gnu-stack,          GNU_STACK,          "The stack is not executable"),
  TEST (optimization,       OPTIMIZATION,       "Compiled with at least -O2"),
  TEST (pic,                PIC,                "All binaries must be compiled with -fPIC or fPIE"),
  TEST (pie,                PIE,                "Executables need to be compiled with -fPIE"),
  TEST (property-note,      PROPERTY_NOTE,      "Correctly formatted GNU Property notes (x86_64)"),
  TEST (run-path,           RUN_PATH,           "All runpath entries are under /usr"),
  TEST (rwx-seg,            RWX_SEG,            "There are no segments that are both writeable and executable"),
  TEST (short-enum,         SHORT_ENUM,         "Compiled with consistent use of -fshort-enum"),
  TEST (stack-clash,        STACK_CLASH,        "Compiled with -fstack-clash-protection (not ARM)"),
  TEST (stack-prot,         STACK_PROT,         "Compiled with -fstack-protector-strong"),
  TEST (stack-realign,      STACK_REALIGN,      "Compiled with -mstackrealign (i686 only)"),
  TEST (textrel,            TEXTREL,            "There are no text relocations in the binary"),
  TEST (threads,            THREADS,            "Compiled with -fexceptions"),
  TEST (warnings,           WARNINGS,           "Compiled with -Wall"),
  TEST (writeable-got,      WRITEABLE_GOT,      "The .got section is not writeable"),
};


static inline bool
built_by_compiler (void)
{
  return per_file.tool == TOOL_GCC
    || per_file.tool == TOOL_CLANG
    || per_file.tool == TOOL_LLVM;
}

static inline bool
built_by_gcc (void)
{
  return per_file.tool == TOOL_GCC;
}

static inline bool
built_by_clang (void)
{
  return per_file.tool == TOOL_CLANG;
}

static inline bool
built_by_mixed (void)
{
  return per_file.tool == TOOL_MIXED;
}

static void
warn (annocheck_data * data, const char * message)
{
  /* We use the VERBOSE setting rather than WARN because that way
     we not get a prefix.  */
  einfo (VERBOSE, "%s: WARN: %s", data->filename, message);
}

static void
info (annocheck_data * data, const char * message)
{
  einfo (VERBOSE, "%s: info: %s", data->filename, message);
}

static bool
start (annocheck_data * data)
{
  /* (Re) Set the results for the tests.  */
  int i;

  for (i = 0; i < TEST_MAX; i++)
    {
      tests [i].num_pass = 0;
      tests [i].num_fail = 0;
      tests [i].num_maybe = 0;
    }

  /* Initialise other per-file variables.  */
  memset (& per_file, 0, sizeof per_file);
  per_file.text_section_name_index = -1;

  if (num_allocated_ranges)
    {
      free (ranges);
      ranges = NULL;
      next_free_range = num_allocated_ranges = 0;
    }

  if (data->is_32bit)
    {
      Elf32_Ehdr * hdr = elf32_getehdr (data->elf);

      per_file.e_type = hdr->e_type;
      per_file.e_machine = hdr->e_machine;
      per_file.e_entry = hdr->e_entry;
      per_file.is_little_endian = hdr->e_ident[EI_DATA] != ELFDATA2MSB;
    }
  else
    {
      Elf64_Ehdr * hdr = elf64_getehdr (data->elf);

      per_file.e_type = hdr->e_type;
      per_file.e_machine = hdr->e_machine;
      per_file.e_entry = hdr->e_entry;
      per_file.is_little_endian = hdr->e_ident[EI_DATA] != ELFDATA2MSB;
    }

  /* We do not expect to find ET_EXEC binaries.  These days all binaries
     should be ET_DYN, even executable programs.  */
  if (per_file.e_type == ET_EXEC && tests[TEST_PIE].enabled)
    tests[TEST_PIE].num_fail ++;

  return true;
}

static bool
interesting_sec (annocheck_data *     data,
		 annocheck_section *  sec)
{
  if (disabled)
    return false;

  /* .dwz files have a .gdb_index section.  */
  if (streq (sec->secname, ".gdb_index"))
    per_file.debuginfo_file = true;

  if (streq (sec->secname, ".text"))
    {
      /* Separate debuginfo files have a .text section with a non-zero
	 size but no contents!  */
      if (sec->shdr.sh_type == SHT_NOBITS && sec->shdr.sh_size > 0)
	per_file.debuginfo_file = true;

      per_file.text_section_name_index = sec->shdr.sh_name;
      per_file.text_section_alignment = sec->shdr.sh_addralign;
      return false; /* We do not actually need to scan the contents of the .text section.  */
    }
  else if (per_file.debuginfo_file)
    return false;

  /* If the file has a stack section then check its permissions.  */
  if (streq (sec->secname, ".stack"))
    {
      if ((sec->shdr.sh_flags & (SHF_WRITE | SHF_EXECINSTR)) == SHF_WRITE)
	++ tests[TEST_GNU_STACK].num_pass;
      else
	++ tests[TEST_GNU_STACK].num_fail;
    }

  /* Note the permissions on GOT/PLT relocation sections.  */
  if (streq  (sec->secname, ".rel.got")
      || streq  (sec->secname, ".rela.got")
      || streq  (sec->secname, ".rel.plt")
      || streq  (sec->secname, ".rela.plt"))
    {
      if (sec->shdr.sh_flags & SHF_WRITE)
	++ tests[TEST_WRITEABLE_GOT].num_fail;
    }

  if (sec->shdr.sh_size == 0)
    return false;

  if (streq (sec->secname, ".comment"))
    return true;

  /* These types of section need further processing.  */
  return sec->shdr.sh_type == SHT_DYNAMIC
    || sec->shdr.sh_type == SHT_NOTE
    || sec->shdr.sh_type == SHT_STRTAB;
}

static bool
interesting_note_sec (annocheck_data *     data,
		      annocheck_section *  sec)
{
  if (disabled)
    return false;

  return sec->shdr.sh_type == SHT_NOTE;
}

static inline unsigned long
align (unsigned long val, unsigned long alignment)
{
  return (val + (alignment - 1)) & (~ (alignment - 1));
}

static const char *
get_component_name (annocheck_data *       data,
		    annocheck_section *    sec,
		    hardened_note_data *   note_data,
		    bool                   prefer_func_symbol)
{
  static char *  buffer = NULL;
  const char *   sym;
  int            res;

  if (buffer != NULL)
    {
      free (buffer);
      buffer = NULL;
    }

  sym = annocheck_find_symbol_for_address_range (data, sec, note_data->start, note_data->end, prefer_func_symbol);

  if (sym == NULL)
    {
      if (note_data->start == note_data->end)
	res = asprintf (& buffer, "address: %#lx", note_data->start);
      else
	res = asprintf (& buffer, "addr range: %#lx..%#lx", note_data->start, note_data->end);
    }
  else
    res = asprintf (& buffer, "component: %s", sym);

  if (res > 0)
    return buffer;
  return NULL;
}

static const char *
stack_prot_type (uint value)
{
  switch (value)
    {
    case 0: return "-fno-stack-protector";
    case 1: return "-fstack-protector";
    case 2: return "-fstack-protector-all";
    case 3: return "-fstack-protector-strong";
    case 4: return "-fstack-protector-explicit";
    default: return "<unknown>";
    }
}

static bool
skip_check (enum test_index check, const char * component_name)
{
  if (check < TEST_MAX && ! tests[check].enabled)
    return true;

  if (component_name == NULL)
    return false;

  if (const_strneq (component_name, "component: "))
    component_name += strlen ("component: ");

  if (streq (component_name, "elf_init.c")
      || streq (component_name, "init.c"))
    {
      if (check < TEST_MAX)
	einfo (VERBOSE2, "skipping test %s for component %s", tests[check].name, component_name);
      return true;
    }

  const static struct ignore
  {
    const char *     func_name;
    enum test_index  test_indicies[4];
  }
  skip_these_funcs[] =
  {
    /* We know that some glibc startup functions cannot be compiled
       with stack protection enabled.  So do not complain about them.  */
    { "_init", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
    { "_fini", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
    { "__libc_csu_init", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
    { "__libc_csu_fini", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
    { "_start", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },

    /* FIXME: Not sure about these two - they need some tests skipping
       but I do not think that they were stack tests...  */
    { "static_reloc.c", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
    { "_dl_relocate_static_pie", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },

    /* The stack overflow support code does not need stack protection.  */
    { "__stack_chk_fail_local", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
    { "stack_chk_fail_local.c", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
   
    /* Also the atexit function in libiberty is only compiled with -fPIC not -fPIE.  */
    { "atexit", { TEST_PIC, TEST_PIE, TEST_MAX, 0 } }
  };

  int i;

  for (i = ARRAY_SIZE (skip_these_funcs); i--;)
    if (streq (component_name, skip_these_funcs[i].func_name))
      {
	for (i = 0; i < ARRAY_SIZE (skip_these_funcs[0].test_indicies); i++)
	  if (skip_these_funcs[0].test_indicies[i] == check)
	    {
	      if (check < TEST_MAX)
		einfo (VERBOSE2, "skipping test %s for component %s", tests[check].name, component_name);
	      else
		einfo (VERBOSE2, "skipping tests of component %s", component_name);
	      return true;
	    }

	/* No need to continue searching - we have already matched the name.  */
	break;
      }

  return false;
}

static void
record_range (ulong start, ulong end)
{
  if (start == end)
    return;

  assert (start < end);

  if (next_free_range >= num_allocated_ranges)
    {
      num_allocated_ranges += RANGE_ALLOC_DELTA;
      size_t num = num_allocated_ranges * sizeof ranges[0];

      if (ranges == NULL)
	ranges = xmalloc (num);
      else
	ranges = xrealloc (ranges, num);
    }

  /* Nothing clever here.  Just record the data.  */
  ranges[next_free_range].start = start;
  ranges[next_free_range].end   = end;
  next_free_range ++;
}

/* Wrapper for einfo that avoids calling get_component_name()
   unless we know that the string will be needed.  */

static void
report_i (einfo_type           type,
	  const char *         format,
	  annocheck_data *     data,
	  annocheck_section *  sec,
	  hardened_note_data * note,
	  bool                 prefer_func,
	  uint                 value)
{
  if (type == VERBOSE2 && ! BE_VERY_VERBOSE)
    return;
  if (type == VERBOSE && ! BE_VERBOSE)
    return;

  einfo (type, format, data->filename, get_component_name (data, sec, note, prefer_func), value);
}
	
static void
report_s (einfo_type           type,
	  const char *         format,
	  annocheck_data *     data,
	  annocheck_section *  sec,
	  hardened_note_data * note,
	  bool                 prefer_func,
	  const char *         value)
{
  if (type == VERBOSE2 && ! BE_VERY_VERBOSE)
    return;
  if (type == VERBOSE && ! BE_VERBOSE)
    return;

  einfo (type, format, data->filename, get_component_name (data, sec, note, prefer_func), value);
}

static const char *
get_producer_name (enum tool tool)
{
  switch (tool)
    {
    default:           return "<unrecognised>";
    case TOOL_UNKNOWN: return "<unknown>";
    case TOOL_MIXED:   return "<mixed>";
    case TOOL_GCC:     return "gcc";
    case TOOL_GAS:     return "gas";
    case TOOL_CLANG:   return "clang";
    case TOOL_LLVM:    return "llvm";
    case TOOL_FORTRAN: return "fortran";
    case TOOL_GO:      return "go";
    case TOOL_RUST:    return "rust";
    }
}

static void
set_producer (annocheck_data *     data,
	      enum tool            tool,
	      unsigned int         version,
	      const char *         source)
{
  einfo (VERBOSE2, "info: Record producer %s version %u source %s", get_producer_name (tool), version, source);

  if (per_file.tool == TOOL_UNKNOWN)
    {
      per_file.tool = tool;
      per_file.version = version;
      einfo (VERBOSE, "%s: info: Set binary producer to %s version %u", data->filename, get_producer_name (tool), version);
    }
  else if (per_file.tool == tool)
    {
      if (per_file.version != version)
	{
	  if (! per_file.warned_producer)
	    {
	      einfo (VERBOSE, "%s: warn: Multiple versions of a tool were used to build this file (%u %u) - using highest version",
		     data->filename, version, per_file.version);
	      per_file.warned_producer = true;
	    }

	  if (per_file.version < version)
	    per_file.version = version;
	}
    }
  else if ((per_file.tool == TOOL_GAS && tool == TOOL_GCC)
	   || (per_file.tool == TOOL_GCC && tool == TOOL_GAS))
    {
      if (! per_file.warned_producer)
	{
	  info (data, "Mixed assembler and GCC detected - treating as pure GCC");
	  per_file.warned_producer = true;
	}

      per_file.tool = TOOL_GCC;
    }
  else if (! built_by_mixed ())
    {
      if (! per_file.warned_producer)
	{
	  einfo (VERBOSE, "%s: info: This binary was built by more than one tool (%s and %s)",
		 data->filename,
		get_producer_name (per_file.tool),
		get_producer_name (tool));
	  per_file.warned_producer = true;
	}

      per_file.tool = TOOL_MIXED;
      per_file.version = 0;
    }
}

struct tool_string
{
  const char * lead_in;
  const char * tool_name;
  enum tool    tool_id;
};

static bool
walk_build_notes (annocheck_data *     data,
		  annocheck_section *  sec,
		  GElf_Nhdr *          note,
		  size_t               name_offset,
		  size_t               data_offset,
		  void *               ptr)
{
  bool                  prefer_func_name;
  hardened_note_data *  note_data;

  if (note->n_type != NT_GNU_BUILD_ATTRIBUTE_OPEN
      && note->n_type != NT_GNU_BUILD_ATTRIBUTE_FUNC)
    {
      einfo (FAIL, "%s: Unrecognised annobin note type %d", data->filename, note->n_type);
      return false;
    }

  prefer_func_name = note->n_type == NT_GNU_BUILD_ATTRIBUTE_FUNC;
  note_data = (hardened_note_data *) ptr;

  if (note->n_namesz < 3)
    {
      einfo (FAIL, "%s: Corrupt annobin note, name size: %x", data->filename, note->n_namesz);
      return false;
    }

  if (note->n_descsz > 0)
    {
      ulong start = 0;
      ulong end = 0;
      const unsigned char * descdata = sec->data->d_buf + data_offset;

      /* FIXME: Should we add support for earlier versions of
	 the annobin notes which did not include an end symbol ?  */

      if (note->n_descsz == 16)
	{
	  int i;
	  int shift;

	  if (per_file.is_little_endian)
	    {
	      for (shift = i = 0; i < 8; i++)
		{
		  ulong byte = descdata[i];

		  start |= byte << shift;
		  byte = descdata[i + 8];
		  end |= byte << shift;

		  shift += 8;
		}
	    }
	  else
	    {
	      for (shift = 0, i = 7; i >= 0; i--)
		{
		  ulong byte = descdata[i];

		  start |= byte << shift;
		  byte = descdata[i + 8];
		  end |= byte << shift;

		  shift += 8;
		}
	    }
	}
      else if (note->n_descsz == 8)
	{
	  if (per_file.is_little_endian)
	    {
	      start = descdata[0]
		| (((ulong) descdata[1]) << 8)
		| (((ulong) descdata[2]) << 16)
		| (((ulong) descdata[3]) << 24);
	      end   = descdata[4]
		| (((ulong) descdata[5]) << 8)
		| (((ulong) descdata[6]) << 16)
		| (((ulong) descdata[7]) << 24);
	    }
	  else
	    {
	      start = descdata[3]
		| (((ulong) descdata[2]) << 8)
		| (((ulong) descdata[1]) << 16)
		| (((ulong) descdata[0]) << 24);
	      end   = descdata[7]
		| (((ulong) descdata[6]) << 8)
		| (((ulong) descdata[5]) << 16)
		| (((ulong) descdata[4]) << 24);
	    }
	}
      else
	{
	  einfo (FAIL, "%s: Corrupt annobin note, desc size: %x",
		 data->filename, note->n_descsz);
	  return false;
	}

      if (start > end)
	{
	  if (per_file.e_machine == EM_PPC64 && (start - end) <= 2)
	    /* On the PPC64, start symbols are biased by 2, but end symbols are not...  */
	    start = end;
	  else
	    {
	      /* We ignore the case where the end address is 0, because this
		 happens when the linker discards a code section but does not
		 discard the notes.  (Eg because annobin is being run with -no-attach
		 enabled).  In such situations the notes should be ignored,
		 because they refer to code that has been discarded.  */
	      if (end == 0)
		return true;

	      einfo (FAIL, "%s: Corrupt annobin note, start address %#lx > end address %#lx",
		     data->filename, start, end);
	      return true;
	    }
	}

      note_data->start = start;
      note_data->end   = end;

      if (per_file.e_type != ET_REL && ! ignore_gaps)
	{
	  /* Notes can occur in any order and may be spread across multiple note
	     sections.  So we record the range covered here and then check for
	     gaps once we have examined all of the notes.  */
	  record_range (start, end);
	}
    }

  /* We skip notes for empty ranges unless we are dealing with unrelocated object files.  */
  if (per_file.e_type != ET_REL && note_data->start == note_data->end)
    return true;

  const char *  namedata = sec->data->d_buf + name_offset;
  uint          pos = (namedata[0] == 'G' ? 3 : 1);
  char          attr_type = namedata[pos - 1];
  const char *  attr = namedata + pos;

  /* Advance pos to the attribute's value.  */
  if (! isprint (* attr))
    pos ++;
  else
    pos += strlen (namedata + pos) + 1;

  const char *  string = namedata + pos;
  uint          value = -1;

  switch (attr_type)
    {
    case GNU_BUILD_ATTRIBUTE_TYPE_NUMERIC:
      {
	uint shift = 0;
	int bytes = (namedata + note->n_namesz) - string;

	value = 0;
	if (bytes > 0)
	  bytes --;
	while (bytes --)
	  {
	    uint byte = (* string ++) & 0xff;

	    /* Note - the watermark protocol dictates that numeric values are
	       always stored in little endian format, even if the target uses
	       big-endian.  */
	    value |= byte << shift;
	    shift += 8;
	  }
      }
      break;
    case GNU_BUILD_ATTRIBUTE_TYPE_STRING:
      break;
    case GNU_BUILD_ATTRIBUTE_TYPE_BOOL_TRUE:
      value = 1;
      break;
    case GNU_BUILD_ATTRIBUTE_TYPE_BOOL_FALSE:
      value = 0;
      break;
    default:
      einfo (VERBOSE, "ICE:  Unrecognised annobin note type %d", attr_type);
      return true;
    }

  switch (* attr)
    {
    case GNU_BUILD_ATTRIBUTE_VERSION:
      if (value != -1)
	{
	  einfo (VERBOSE, "ICE:  The version note should have a string attribute");
	  break;
	}

      /* Check the Watermark protocol revision.  */
      ++ attr;
      if (* attr <= '0')
	{
	  einfo (VERBOSE, "ICE:  The version contains an invalid specification number: %d", * attr - '0');
	  break;
	}

      if (* attr > '0' + SPEC_VERSION)
	einfo (WARN, "%s: This checker only supports version %d of the Watermark protocol.  The data in the notes uses version %d",
	       data->filename, SPEC_VERSION, * attr - '0');

      /* Check the note per_file.  */
      ++ attr;
      switch (* attr)
	{
	case ANNOBIN_TOOL_ID_ASSEMBLER:
	case ANNOBIN_TOOL_ID_LINKER:
	  break;
	case ANNOBIN_TOOL_ID_GCC_HOT:
	case ANNOBIN_TOOL_ID_GCC_COLD:
	case ANNOBIN_TOOL_ID_GCC_STARTUP:
	case ANNOBIN_TOOL_ID_GCC_EXIT:
	case ANNOBIN_TOOL_ID_GCC:
	  /* FIXME: Add code to check that the version of the
	     note producer is not greater than our version.  */

	  /* Note that we have seen compiler generated code.  (As opposed
	     to assembler or linker generated code).  This means that we
	     can expect to see notes for -D_FROTIFY_SOURCE and -D_GLIBCXX_ASSERTIONS,
	     and if they are missing, we can complain.  We do not use
	     the value of per_file.tool because if the assembler source was
	     built using gcc then it will have debug information associated
	     with it, with a DW_AT_PRODUCER string that includes the *gcc*
	     version number.  */
	  per_file.compiled_code_seen = true;
	  break;
	case ANNOBIN_TOOL_ID_LLVM:
	case ANNOBIN_TOOL_ID_CLANG:
	  per_file.compiled_code_seen = true;
	  break;
	default:
	  warn (data, "Unrecognised annobin note producer");
	  break;
	}
      break;

    case GNU_BUILD_ATTRIBUTE_TOOL:
      if (value != -1)
	{
	  einfo (VERBOSE, "ICE:  The tool note should have a string attribute");
	  break;
	}

      /* Parse the tool attribute looking for the version of gcc used to build the component.  */
      unsigned major, minor, rel;
      
      /* As of version 8.80 there are two BUILT_ATTRIBUTE_TOOL version strings,
	 one for the compiler that built the annobin plugin and one for the
	 compiler that ran the annobin plugin.  Look for these here.  Their
	 format is "annobin gcc X.Y.Z DATE" and "running gcc X.Y.Z DATE".  */
      static struct tool_string run_tool_strings [] =
	{
	 { "running gcc ", "gcc", TOOL_GCC },
	 { "running on clang version ", "clang", TOOL_CLANG },
	 { "running on LLVM version ", "llvm", TOOL_LLVM }
	};

      int i;
      for (i = ARRAY_SIZE (run_tool_strings); i--;)
	{
	  struct tool_string * t = run_tool_strings + i;

	  if (strncmp (attr + 1, t->lead_in, strlen (t->lead_in)) != 0)
	    continue;
	    
	  if (sscanf (attr + 1 + strlen (t->lead_in), "%u.%u.%u", & major, & minor, & rel) != 3)
	    {
	      einfo (VERBOSE2, "lead in '%s' matched, but conversion failed.  Full string: '%s'", t->lead_in, attr + 1);
	      continue;
	    }

	  einfo (VERBOSE2, "%s: info: Detected information created by an annobin plugin running on %s version %u.%u.%u",
		 data->filename, t->tool_name, major, minor, rel);

	  if (per_file.run_major == 0)
	    {
	      per_file.run_major = major;
	      set_producer (data, t->tool_id, major, "GNU Build Attribute Tool");
	    }
	  else if (per_file.run_major != major)
	    {
	      einfo (INFO, "%s: WARN: this file was built by more than one version of %s (%u and %u)",
		     data->filename, t->tool_name, per_file.run_major, major);
	      if (per_file.run_major < major)
		per_file.run_major = major;
	    }

	  if (per_file.anno_major != 0 && per_file.anno_major != per_file.run_major)
	    {
	      if (! per_file.warned_version_mismatch)
		{
		  einfo (INFO, "%s: ICE:  Annobin plugin was built by %s version %u but run on %s version %u",
			 data->filename, t->tool_name, per_file.anno_major,
			 t->tool_name, per_file.run_major);
		  per_file.warned_version_mismatch = true;
		}
	    }

	  per_file.run_minor = minor;
	  per_file.run_rel = rel;
	  if ((per_file.anno_minor != 0 && per_file.anno_minor != minor)
	      || (per_file.anno_rel != 0 && per_file.anno_rel != rel))
	    {
	      einfo (VERBOSE, "%s: warn: Annobin plugin was built by %s %u.%u.%u but run on %s version %u.%u.%u",
		     data->filename, t->tool_name,
		     per_file.anno_major, per_file.anno_minor, per_file.anno_rel,
		     t->tool_name,
		     per_file.run_major, per_file.run_minor, per_file.run_rel);
	      einfo (VERBOSE, "%s: warn: If there are FAIL results that appear to be incorrect, it could be due to this discrepancy.",
		     data->filename);
	    }
	  break;
	}

      if (i >= 0)
	break;

      static struct tool_string build_tool_strings [] =
	{
	 { "annobin gcc ", "gcc", TOOL_GCC },
	 { "annobin built by clang version ", "clang", TOOL_CLANG },
	 { "annobin built by llvm version ", "llvm", TOOL_LLVM }
	};

      for (i = ARRAY_SIZE (build_tool_strings); i--;)
	{
	  struct tool_string * t = build_tool_strings + i;

	  if (strncmp (attr + 1, t->lead_in, strlen (t->lead_in)) != 0)
	    continue;
	    
	  if (sscanf (attr + 1 + strlen (t->lead_in), "%u.%u.%u", & major, & minor, & rel) != 3)
	    {
	      einfo (VERBOSE2, "lead in '%s' matched, but conversion failed.  Full string: '%s'", t->lead_in, attr + 1);
	      continue;
	    }

	  einfo (VERBOSE2, "%s: info: Detected information stored by an annobin plugin built by %s version %u.%u.%u",
		 data->filename, t->tool_name, major, minor, rel);

	  if (per_file.anno_major == 0)
	    {
	      per_file.anno_major = major;
	    }
	  else if (per_file.anno_major != major)
	    {
	      einfo (INFO, "%s: WARN: notes produced by annobins compiled for more than one version of %s (%u vs %u)",
		     data->filename, t->tool_name, per_file.anno_major, major);
	      if (per_file.anno_major < major)
		per_file.anno_major = major;
	    }

	  if (per_file.run_major != 0 && per_file.run_major != per_file.anno_major)
	    {
	      if (! per_file.warned_version_mismatch)
		{
		  einfo (INFO, "%s: ICE:  Annobin plugin was built by %s version %u but run on %s version %u",
			 data->filename, t->tool_name, per_file.anno_major, t->tool_name, per_file.run_major);
		  per_file.warned_version_mismatch = true;
		}
	    }

	  per_file.anno_minor = minor;
	  per_file.anno_rel = rel;
	  if ((per_file.run_minor != 0 && per_file.run_minor != minor)
	      || (per_file.run_rel != 0 && per_file.run_rel != rel))
	    {
	      einfo (VERBOSE, "%s: warn: Annobin plugin was built by %s %u.%u.%u but run on %s version %u.%u.%u",
		     data->filename, t->tool_name, per_file.anno_major, per_file.anno_minor, per_file.anno_rel,
		     t->tool_name, per_file.run_major, per_file.run_minor, per_file.run_rel);
	      einfo (VERBOSE, "%s: warn: If there are FAIL results that appear to be incorrect, it could be due to this discrepancy.",
		     data->filename);
	    }

	  break;
	}
      if (i >= 0)
	break;

      /* Otherwise look for the normal BUILD_ATTRIBUTE_TOOL string.  */
      const char * gcc = strstr (attr + 1, "gcc");

      if (gcc != NULL)
	{
	  /* FIXME: This assumes that the tool string looks like: "gcc 7.x.x......"  */
	  unsigned int version = (unsigned int) strtoul (gcc + 4, NULL, 10);

	  report_i (VERBOSE2, "%s: (%s) built-by gcc version %u",
		    data, sec, note_data, prefer_func_name, version);

	  set_producer (data, TOOL_GCC, version, "GNU Build Attribute");
	}
      else
	report_s (VERBOSE, "%s: (%s) unable to parse tool attribute: %s",
		  data, sec, note_data, prefer_func_name, attr);
      break;

    case GNU_BUILD_ATTRIBUTE_PIC:
      if (value < 3
	  && (value < 1 || per_file.e_type == ET_EXEC)
	  && skip_check (TEST_PIC, get_component_name (data, sec, note_data, prefer_func_name)))
	break;

      /* Convert the pic value into a pass/fail result.  */
      switch (value)
	{
	case -1:
	default:
	  report_i (VERBOSE, "%s: MAYB: (%s): unexpected value for PIC note (%x)",
		    data, sec, note_data, prefer_func_name, value);
	  tests[TEST_PIC].num_maybe ++;
	  break;

	case 0:
	  report_s (VERBOSE, "%s: FAIL: (%s): compiled without -fPIC/-fPIE",
		  data, sec, note_data, prefer_func_name, NULL);
	  tests[TEST_PIC].num_fail ++;
	  break;

	case 1:
	case 2:
	  /* Compiled wth -fpic not -fpie.  */
	  if (per_file.e_type == ET_EXEC)
	    {
#if 0 /* Suppressed because ET_EXEC will already generate a failure...  */
	      /* Building an executable with -fPIC rather than -fPIE is a bad thing
		 as it means that the executable is located at a known address that
		 can be exploited by an attacker.  Linking against shared libraries
		 compiled with -fPIC is OK, since they expect to have their own
		 address space, but linking against static libraries compiled with
		 -fPIC is still bad.  But ... compiling with -fPIC but then linking
		 with -fPIE is OK.  It is the final result that matters.  However
		 we have already checked the e_type above and know that it is ET_EXEC,
		 ie, not a PIE executable, so this result is a FAIL.  */
	      report_s (VERBOSE, "%s: FAIL: (%s): compiled with -fPIC rather than -fPIE",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_PIC].num_fail ++;
#endif
	    }
	  else
	    {
	      report_s (VERBOSE2, "%s: PASS: (%s): compiled with -fPIC/-fPIE",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_PIC].num_pass ++;
	    }
	  break;

	case 3:
	case 4:
	  report_s (VERBOSE2, "%s: PASS: (%s): compiled with -fPIE",
		    data, sec, note_data, prefer_func_name, NULL);
	  tests[TEST_PIC].num_pass ++;
	  break;
	}
      break;

    case GNU_BUILD_ATTRIBUTE_STACK_PROT:
      if (value != 2 && value != 3
	  && skip_check (TEST_STACK_PROT, get_component_name (data, sec, note_data, prefer_func_name)))
	break;

      /* We can get stack protection notes without tool notes.  See BZ 1703788 for an example.  */
      if (value != 2 && value != 3 && ! built_by_compiler ())
	{
	  report_s (VERBOSE, "%s: skip: (%s): Insufficient stack protection (%s) - ignoring because not in compiled code",
		    data, sec, note_data, prefer_func_name, stack_prot_type (value));
	  break;
	}

      switch (value)
	{
	case -1:
	default:
	  report_i (VERBOSE, "%s: MAYB: (%s): unexpected value for stack protection note (%x)",
		  data, sec, note_data, prefer_func_name, value);
	  tests[TEST_STACK_PROT].num_maybe ++;
	  break;

	case 0: /* NONE */
	  report_s (VERBOSE, "%s: FAIL: (%s): No stack protection enabled",
		    data, sec, note_data, prefer_func_name, NULL);
	  tests[TEST_STACK_PROT].num_fail ++;
	  break;

	case 1: /* BASIC (funcs using alloca or with local buffers > 8 bytes) */
	case 4: /* EXPLICIT */
	  report_s (VERBOSE, "%s: FAIL: (%s): Insufficient stack protection: %s",
		    data, sec, note_data, prefer_func_name, stack_prot_type (value));
	  tests[TEST_STACK_PROT].num_fail ++;
	  break;

	case 2: /* ALL */
	case 3: /* STRONG */
	  report_s (VERBOSE2, "%s: PASS: (%s): %s enabled",
		    data, sec, note_data, prefer_func_name, stack_prot_type (value));
	  tests[TEST_STACK_PROT].num_pass ++;
	  break;
	}
      break;

    case GNU_BUILD_ATTRIBUTE_SHORT_ENUM:
#if 0 /* There is no valid reason to skip this test.  */
      if (skip_check (TEST_SHORT_ENUM, get_component_name (data, sec, note_data, prefer_func_name)))
	break;
#endif
      if (value == 1)
	{
	  tests[TEST_SHORT_ENUM].num_fail ++;

	  if (tests[TEST_SHORT_ENUM].num_pass)
	    report_i (VERBOSE, "%s: FAIL: (%s): different -fshort-enum option used",
		      data, sec, note_data, prefer_func_name, value);
	}
      else if (value == 0)
	{
	  tests[TEST_SHORT_ENUM].num_pass ++;

	  if (tests[TEST_SHORT_ENUM].num_fail)
	    report_i (VERBOSE, "%s: FAIL: (%s): different -fshort-enum option used",
		      data, sec, note_data, prefer_func_name, value);
	}
      else
	{
	  report_i (VERBOSE, "%s: MAYB: (%s): unexpected value for short-enum note (%x)",
		    data, sec, note_data, prefer_func_name, value);
	  tests[TEST_SHORT_ENUM].num_maybe ++;
	}
      break;

    case 'b':
      if (const_strneq (attr, "branch_protection:"))
	{
	  if (per_file.e_machine != EM_AARCH64)
	    break;

	  attr += strlen ("branch_protection:");
	  if (* attr == 0
	      || streq (attr, "(null)")
	      || streq (attr, "default"))
	    {
	      if (skip_check (TEST_BRANCH_PROTECTION, get_component_name (data, sec, note_data, prefer_func_name)))
		break;

	      /* FIXME: Turn into a FAIL once -mbranch-protection is required by the security spec.  */
	      report_s (VERBOSE, "%s: info: (%s): Compiled without -mbranch-protection",
			data, sec, note_data, prefer_func_name, NULL);
	      /* tests[TEST_BRANCH_PROTECTION].num_fail ++; */
	      break;
	    }
	  else if (streq (attr, "bti")
		   || (streq (attr, "standard"))
		   || const_strneq (attr, "pac-ret"))
	    {
	      report_s (VERBOSE2, "%s: PASS: (%s): branch-protection enabled (%s)",
			data, sec, note_data, prefer_func_name, attr);
	      tests[TEST_BRANCH_PROTECTION].num_pass ++;
	    }
	  else if (streq (attr, "none"))
	    {
	      if (skip_check (TEST_BRANCH_PROTECTION, get_component_name (data, sec, note_data, prefer_func_name)))
		break;

	      report_s (VERBOSE, "%s: FAIL: (%s): Compiled with -mbranch-protection=none",
			data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_BRANCH_PROTECTION].num_fail ++;
	      break;
	    }
	  else
	    {
	      if (skip_check (TEST_BRANCH_PROTECTION, get_component_name (data, sec, note_data, prefer_func_name)))
		break;

	      report_s (VERBOSE, "%s: MAYB: (%s): unexpected value for branch-protection note (%s)",
			data, sec, note_data, prefer_func_name, attr);
	      tests[TEST_BRANCH_PROTECTION].num_maybe ++;
	      break;
	    }
	}
      else
	einfo (VERBOSE2, "Unsupport annobin note '%s' - ignored", attr);
      break;

    case 'c':
      if (streq (attr, "cf_protection"))
	{
	  if (per_file.e_machine != EM_386 && per_file.e_machine != EM_X86_64)
	    break;

	  if (value != 4 && value != 8
	      && skip_check (TEST_CF_PROTECTION, get_component_name (data, sec, note_data, prefer_func_name)))
	    break;

	  switch (value)
	    {
	    case -1:
	    default:
	      report_i (VERBOSE, "%s: MAYB: (%s): unexpected value for cf-protection note (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_CF_PROTECTION].num_maybe ++;
	      break;

	      /* Note - the annobin plugin adds one to the value of gcc's flag_cf_protection,
		 thus a setting of CF_FULL (3) is actually recorded as 4, and so on.  */

	    case 4: /* CF_FULL.  */
	    case 8: /* CF_FULL | CF_SET */
	      report_i (VERBOSE2, "%s: PASS: (%s): cf-protection enabled (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_CF_PROTECTION].num_pass ++;
	      break;

	    case 2: /* CF_BRANCH: Branch but not return.  */
	    case 6: /* CF_BRANCH | CF_SET */
	      report_s (VERBOSE, "%s: FAIL: (%s): Only compiled with -fcf-protection=branch",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_CF_PROTECTION].num_fail ++;
	      break;

	    case 3: /* CF_RETURN: Return but not branch.  */
	    case 7: /* CF_RETURN | CF_SET */
	      report_s (VERBOSE, "%s: FAIL: (%s): Only compiled with -fcf-protection=return",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_CF_PROTECTION].num_fail ++;
	      break;

	    case 1: /* CF_NONE: No protection. */
	    case 5: /* CF_NONE | CF_SET */
	      report_s (VERBOSE, "%s: FAIL: (%s): Compiled without -fcf-protection",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_CF_PROTECTION].num_fail ++;
	      break;
	    }
	}
      else
	einfo (VERBOSE2, "Unsupport annobin note '%s' - ignored", attr);
      break;

    case 'F':
      if (streq (attr, "FORTIFY"))
	{
	  if (value != 2
	      && skip_check (TEST_FORTIFY, get_component_name (data, sec, note_data, prefer_func_name)))
	    break;

	  switch (value)
	    {
	    case -1:
	    default:
	      report_i (VERBOSE, "%s: MAYB: (%s): unexpected value for fortify note (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_FORTIFY].num_maybe ++;
	      break;

	    case 0xff:
	      /* BZ 1824393: We	have not scanned the DWARF notes yet, so we may	                                                  
	      	 not have the full picture as to which tool(s) built this binary.  */   
              report_s (VERBOSE, "%s: MAYB: (%s): -D_FORTIFY_SOURCE not detected on the command line",
                        data, sec, note_data, prefer_func_name, NULL);
	      einfo (VERBOSE,    "%s:       This can happen if the source does not use C headers",
		     data->filename);
 	      tests[TEST_FORTIFY].num_maybe ++;
	      break;

	    case 0:
	    case 1:
	      report_i (VERBOSE, "%s: FAIL: (%s): Insufficient value for -D_FORTIFY_SOURCE: %d",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_FORTIFY].num_fail ++;
	      break;

	    case 2:
	      report_s (VERBOSE2, "%s: PASS: (%s): -D_FORTIFY_SOURCE=2",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_FORTIFY].num_pass ++;
	      break;
	    }
	}
      else
	einfo (VERBOSE2, "Unsupport annobin note '%s' - ignored", attr);
      break;

    case 'G':
      if (streq (attr, "GOW"))
	{
	  if (value == -1)
	    {
	      report_i (VERBOSE, "%s: MAYB: (%s): unexpected value for optimize note (%x)",
			data, sec, note_data, prefer_func_name, value);
	      tests[TEST_OPTIMIZATION].num_maybe ++;
	    }
	  else
	    {
	      if (value & (1 << 13))
		{
		  /* Compiled with -Og rather than -O2.
		     Treat this as a flag to indicate that the package developer is
		     intentionally not compiling with -O2, so suppress warnings about it.  */
		  report_i (VERBOSE, "%s: skip: (%s): compiled with -Og, so ignoring test for -O2+",
			    data, sec, note_data, prefer_func_name, value);
		  /* Add a pass result so that we do not complain about lack of optimization information.  */
		  tests[TEST_OPTIMIZATION].num_pass ++;
		}
	      else
		{
		  uint opt = (value >> 9) & 3;

		  if (opt == 0 || opt == 1)
		    {
		      if (! skip_check (TEST_OPTIMIZATION, get_component_name (data, sec, note_data, prefer_func_name)))
			{
			  report_i (VERBOSE, "%s: FAIL: (%s): Insufficient optimization level: -O%d",
				    data, sec, note_data, prefer_func_name, opt);
			  tests[TEST_OPTIMIZATION].num_fail ++;
			}
		    }
		  else /* opt == 2 || opt == 3 */
		    {
		      report_i (VERBOSE2, "%s: PASS: (%s): Sufficient optimization level: -O%d",
				data, sec, note_data, prefer_func_name, opt);
		      tests[TEST_OPTIMIZATION].num_pass ++;
		    }
		}

	      if (value & (1 << 14))
		{
		  /* Compiled with -Wall.  */
		  if (value & (1 << 15))
		    {
		      report_i (VERBOSE2, "%s: PASS: (%s): Compiled with -Wall and -Wformat-security",
				data, sec, note_data, prefer_func_name, value);
		      tests[TEST_WARNINGS].num_pass ++;
		    }
		  else
		    {
		      /* Compiled without -Wformat-security.
			 Not a failure because parts of glibc are compiled with way
			 and because recording of -Wformat-security only started with annobin v8.84.  */
		      report_i (VERBOSE2, "%s: PASS: (%s): Compiled with -Wall",
				data, sec, note_data, prefer_func_name, value);
		      tests[TEST_WARNINGS].num_pass ++;
		    }
		}
	      else if (value & (1 << 15))
		{
		  /* Compiled with -Wformat-security but not -Wall.
		     FIXME: We allow this for now, but really would should check for
		     any warnings enabled by -Wall that are important.  (Missing -Wall
		     itself is not bad - this happens with LTO compilation - but we
		     still want important warnings enabled).  */
		  report_i (VERBOSE2, "%s: PASS: (%s): Compiled with -Wformat-security (but not -Wall)",
			    data, sec, note_data, prefer_func_name, value);
		  tests[TEST_WARNINGS].num_pass ++;
		}
	      else
		{
		  /* FIXME: At the moment the clang plugin is unable to detect -Wall.
		     for clang v9+.  */
		  if (built_by_clang () && per_file.version > 8)
		    break;
		  if (built_by_mixed ())
		    break;

		  if (! skip_check (TEST_WARNINGS, get_component_name (data, sec, note_data, prefer_func_name)))
		    {
		      report_i (VERBOSE, "%s: FAIL: (%s): Compiled without either -Wall or -Wformat-security",
				data, sec, note_data, prefer_func_name, value);
		      tests[TEST_WARNINGS].num_fail ++;
		    }
		}
	    }
	}
      else if (streq (attr, "GLIBCXX_ASSERTIONS"))
	{
	  if (value != 1
	      && skip_check (TEST_GLIBCXX_ASSERTIONS, get_component_name (data, sec, note_data, prefer_func_name)))
	    break;

	  switch (value)
	    {
	    case 0:
	      report_s (VERBOSE, "%s: FAIL: (%s): Compiled without -D_GLIBCXX_ASSERTIONS",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_GLIBCXX_ASSERTIONS].num_fail ++;
	      break;

	    case 1:
	      report_s (VERBOSE2, "%s: PASS: (%s): Compiled with -D_GLIBCXX_ASSERTIONS",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_GLIBCXX_ASSERTIONS].num_pass ++;
	      break;

	    default:
	      report_i (VERBOSE, "%s: MAYB: (%s): unexpected value for glibcxx_assertions note (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_GLIBCXX_ASSERTIONS].num_maybe ++;
	      break;
	    }
	}
      else
	einfo (VERBOSE2, "Unsupport annobin note '%s' - ignored", attr);
      break;

    case 'I':
      if (const_strneq (attr, "INSTRUMENT:"))
	{
	  if (! per_file.warned_about_instrumentation)
	    {
	      report_s (INFO, "%s: WARN: (%s): Instrumentation enabled - this is probably a mistake for production binaries",
			data, sec, note_data, prefer_func_name, NULL);
	      per_file.warned_about_instrumentation = false;

	      if (BE_VERBOSE)
		{
		  unsigned int sanitize, instrument, profile, arcs;

		  attr += strlen ("INSTRUMENT:");
		  if (sscanf (attr, "%u/%u/%u/%u", & sanitize, & instrument, & profile, & arcs) != 4)
		    {
		      report_s (VERBOSE, "%s: ICE:  (%s): Unable to extract details from instrumentation note",
				data, sec, note_data, prefer_func_name, NULL);
		    }
		  else
		    {
		      einfo (VERBOSE, "%s: info: (%s):  Details: -fsanitize=...: %s",
			     data->filename, get_component_name (data, sec, note_data, prefer_func_name),
			     sanitize ? "enabled" : "disabled");
		      einfo (VERBOSE, "%s: info: (%s):  Details: -finstrument-functions: %s",
			     data->filename, get_component_name (data, sec, note_data, prefer_func_name),
			     instrument ? "enabled" : "disabled");
		      einfo (VERBOSE, "%s: info: (%s):  Details: -p and/or -pg: %s",
			     data->filename, get_component_name (data, sec, note_data, prefer_func_name),
			     profile ? "enabled" : "disabled");
		      einfo (VERBOSE, "%s: info: (%s):  Details: -fprofile-arcs: %s",
			     data->filename, get_component_name (data, sec, note_data, prefer_func_name),
			     arcs ? "enabled" : "disabled");
		    }
		}
	      else
		report_s (INFO, "%s: info: (%s):  Run with -v for more information",
			  data, sec, note_data, prefer_func_name, NULL);
	    }
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;
      
    case 's':
      if (streq (attr, "stack_clash"))
	{
	  if (per_file.e_machine == EM_ARM)
	    break;

	  if (value != 1
	      && skip_check (TEST_STACK_CLASH, get_component_name (data, sec, note_data, prefer_func_name)))
	    break;

	  switch (value)
	    {
	    case 0:
	      report_s (VERBOSE, "%s: FAIL: (%s): Compiled without -fstack-clash-protection",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_STACK_CLASH].num_fail ++;
	      break;

	    case 1:
	      report_s (VERBOSE2, "%s: PASS: (%s): Compiled with -fstack-clash-protection",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_STACK_CLASH].num_pass ++;
	      break;

	    default:
	      report_i (VERBOSE, "%s: MAYB: (%s): unexpected value for stack-clash note (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_STACK_CLASH].num_maybe ++;
	      break;
	    }
	}
      else if (streq (attr, "stack_realign"))
	{
	  if (per_file.e_machine != EM_386)
	    break;

	  if (value != 2
	      && skip_check (TEST_STACK_REALIGN, get_component_name (data, sec, note_data, prefer_func_name)))
	    break;

	  switch (value)
	    {
	    case -1:
	      report_i (VERBOSE, "%s: MAYB: (%s): unexpected value for stack realign note (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_STACK_REALIGN].num_maybe ++;
	      break;

	    case 0:
	      report_s (VERBOSE, "%s: FAIL: (%s): Compiled without -fstack-realign",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_STACK_REALIGN].num_fail ++;
	      break;

	    case 1:
	      report_s (VERBOSE2, "%s: PASS: (%s): Compiled with -fstack-realign",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_STACK_REALIGN].num_pass ++;
	      break;
	    }
	}
      else if (streq (attr, "sanitize_cfi"))
	{
	  if (value < 1
	      && skip_check (TEST_CF_PROTECTION, get_component_name (data, sec, note_data, prefer_func_name)))
	    break;

	  if (! built_by_clang() && ! built_by_mixed ())
	    report_s (VERBOSE, "%s: WARN: (%s): Control flow sanitization note found, but the compiler is not clang",
		      data, sec, note_data, prefer_func_name, NULL);

	  if (value < 1)
	    {
	      report_s (VERBOSE, "%s: FAIL: (%s): Compiled with insufficient Control Flow sanitization",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_CF_PROTECTION].num_fail ++;
	    }
	  else /* FIXME: Should we check that specific sanitizations are enabled ?  */
	    {
	      report_s (VERBOSE2, "%s: PASS: (%s): Compiled with sufficient Control Flow sanitization",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_CF_PROTECTION].num_pass ++;
	    }
	  break;
	}
      else if (streq (attr, "sanitize_safe_stack"))
	{
	  if (value < 1
	      && skip_check (TEST_STACK_PROT, get_component_name (data, sec, note_data, prefer_func_name)))
	    break;

	  if (! built_by_clang() && ! built_by_mixed ())
	    report_s (VERBOSE, "%s: WARN: (%s): Stack protection sanitization note found, but the compiler is not clang",
		      data, sec, note_data, prefer_func_name, NULL);

	  if (value < 1)
	    {
	      report_s (VERBOSE, "%s: FAIL: (%s): Compiled with insufficient Stack Safe sanitization",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_STACK_PROT].num_fail ++;
	    }
	  else
	    {
	      report_s (VERBOSE2, "%s: PASS: (%s): Compiled with sufficient Stack Safe sanitization",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_STACK_PROT].num_pass ++;
	    }
	  break;
	}
      else
	einfo (VERBOSE2, "Unsupport annobin note '%s' - ignored", attr);
      break;

    case 'o':
      if (streq (attr, "omit_frame_pointer"))
	/* FIXME: Do Something! */
	break;
      /* Fall through.  */

    default:
      einfo (VERBOSE2, "Unsupport annobin note '%s' - ignored", attr);
      break;

    case GNU_BUILD_ATTRIBUTE_RELRO:
    case GNU_BUILD_ATTRIBUTE_ABI:
    case GNU_BUILD_ATTRIBUTE_STACK_SIZE:
      break;
    }

  return true;
}

static bool
walk_property_notes (annocheck_data *     data,
		     annocheck_section *  sec,
		     GElf_Nhdr *          note,
		     size_t               name_offset,
		     size_t               data_offset,
		     void *               ptr)
{
  if (skip_check (TEST_PROPERTY_NOTE, NULL))
    return true;

  if (note->n_type != NT_GNU_PROPERTY_TYPE_0)
    {
      einfo (VERBOSE, "%s: FAIL: Unexpected GNU Property note type (%x)", data->filename, note->n_type);
      tests[TEST_PROPERTY_NOTE].num_fail ++;
      return false;
    }
  else
    {
      if (per_file.e_type == ET_EXEC || per_file.e_type == ET_DYN)
	{
	  /* More than one note in an executable is an error.  */
	  if (tests[TEST_PROPERTY_NOTE].num_pass)
	    {
	      einfo (VERBOSE, "%s: FAIL: More than one GNU Property note.  (Loader will not enable CET)", data->filename);
	      tests[TEST_PROPERTY_NOTE].num_fail ++;
	      return false;
	    }
	}

      /* FIXME: Add test for CET enablement bit ?  */

      tests[TEST_PROPERTY_NOTE].num_pass ++;
    }

  return true;
}

static bool
check_note_section (annocheck_data *    data,
		    annocheck_section * sec)
{
  if (sec->shdr.sh_addralign != 4 && sec->shdr.sh_addralign != 8)
    {
      einfo (ERROR, "%s: note section %s not properly aligned (alignment: %ld)",
	     data->filename, sec->secname, (long) sec->shdr.sh_addralign);
    }

  if (const_strneq (sec->secname, GNU_BUILD_ATTRS_SECTION_NAME))
    {
      hardened_note_data hard_data;

      hard_data.start = 0;
      hard_data.end = 0;

      per_file.build_notes_seen = true;
      return annocheck_walk_notes (data, sec, walk_build_notes, (void *) & hard_data);
    }

  if (per_file.e_machine == EM_X86_64 && streq (sec->secname, ".note.gnu.property"))
    {
      return annocheck_walk_notes (data, sec, walk_property_notes, NULL);
    }

  if (streq (sec->secname, ".note.go.buildid"))
    {
      set_producer (data, TOOL_GO, 0, ".note.go.buildid");
    }

  return true;
}

static bool
check_string_section (annocheck_data *    data,
		      annocheck_section * sec)
{
  /* Check the string table to see if it contains "__pthread_register_cancel".
     This is not as accurate as checking for a function symbol with this name,
     but it is a lot faster.  */
  if (strstr ((const char *) sec->data->d_buf, "__pthread_register_cancel"))
    tests[TEST_THREADS].num_fail ++;

  return true;
}

/* Returns TRUE iff STR contains a search path that does not start with /usr.
   We also allow $ORIGIN as that is allowed for non-suid binaries.  The
   $LIB and $PLATFORM pseudo-variables should always be used with a /usr
   prefix, so we do not need to check for them.  */

static bool
not_rooted_at_usr (const char * str)
{
  while (str)
    {
      if (! const_strneq (str, "/usr") && ! const_strneq (str, "$ORIGIN"))
	return true;
      str = strchr (str, ':');
      if (str)
	str++;
    }
  return false;
}

static bool
check_dynamic_section (annocheck_data *    data,
		       annocheck_section * sec)
{
  if (sec->shdr.sh_size == 0 || sec->shdr.sh_entsize == 0)
    {
      einfo (VERBOSE, "%s: WARN: Dynamic section %s is empty - ignoring", data->filename, sec->secname);
      return true;
    }

  if (tests[TEST_DYNAMIC].num_pass == 0)
    {
      tests[TEST_DYNAMIC].num_pass = 1;
    }
  else
    {
      einfo (VERBOSE, "%s: FAIL: contains multiple dynamic sections", data->filename);
      tests[TEST_DYNAMIC].num_fail ++;
    }

  size_t num_entries = sec->shdr.sh_size == 0 / sec->shdr.sh_entsize;

  /* Walk the dynamic tags.  */
  while (num_entries --)
    {
      GElf_Dyn   dynmem;
      GElf_Dyn * dyn = gelf_getdyn (sec->data, num_entries, & dynmem);

      if (dyn == NULL)
	break;

      switch (dyn->d_tag)
	{
	case DT_BIND_NOW:
	  tests[TEST_BIND_NOW].num_pass ++;
	  break;

	case DT_FLAGS:
	  if (dyn->d_un.d_val & DF_BIND_NOW)
	    tests[TEST_BIND_NOW].num_pass ++;
	  break;

	case DT_RELSZ:
	case DT_RELASZ:
	  if (dyn->d_un.d_val > 0)
	    tests[TEST_BIND_NOW].num_maybe ++;
	  break;
	      
	case DT_TEXTREL:
	  tests[TEST_TEXTREL].num_fail ++;
	  break;

	case DT_RPATH:
	case DT_RUNPATH:
	  {
	    if (skip_check (TEST_RUN_PATH, NULL))
	      break;

	    const char * path = elf_strptr (data->elf, sec->shdr.sh_link, dyn->d_un.d_val);

	    if (not_rooted_at_usr (path))
	      {
		einfo (VERBOSE, "%s: FAIL: Bad runpath: %s", data->filename, path);
		tests[TEST_RUN_PATH].num_fail ++;
	      }
	  }
	  break;

	default:
	  break;
	}
    }

  return true;
}

static bool
check_comment_section (annocheck_data *     data,
		       annocheck_section *  sec)
{
  if (sec->data->d_size <= 11 || ! streq (sec->secname, ".comment"))
    return true;

  const char * tool = (const char *) sec->data->d_buf;
  const char * tool_end = tool + sec->data->d_size;

  if (tool[0] == 0)
    tool ++; /* Not sure why this can happen, but it does.  */

  /* Note - it is possible to have multiple builder IDs in the .comment section.
     eg:  GCC: (GNU) 8.3.1 20191121 (Red Hat 8.3.1-5)\0GCC: (GNU) 9.2.1 20191120 (Red Hat 9.2.1-2).
     so we keep scanning until we do not find any more.  */
  while (tool < tool_end)
    {
      static const char * gcc_prefix = "GCC: (GNU) ";
      static const char * clang_prefix = "clang version ";
      static const char * lld_prefix = "Linker: LLD ";
      unsigned int version;
      const char * where;

      if ((where = strstr (tool, gcc_prefix)) != NULL)
	{
	  /* FIXME: This assumes that the gcc identifier looks like: "GCC: (GNU) 8.1.1""  */
	  version = (unsigned int) strtod (where + strlen (gcc_prefix), NULL);
	  set_producer (data, TOOL_GCC, version, "comment section");
	  einfo (VERBOSE2, "%s: built by gcc version %u (extracted from '%s' in comment section)",
		 data->filename, version, where);
	}
      else if ((where = strstr (tool, clang_prefix)) != NULL)
	{
	  /* FIXME: This assumes that the clang identifier looks like: "clang version 7.0.1""  */
	  version = (unsigned int) strtod (where + strlen (clang_prefix), NULL);
	  set_producer (data, TOOL_CLANG, version, "comment section");
	  einfo (VERBOSE2, "%s: built by clang version %u (extracted from '%s' in comment section)",
		 data->filename, version, where);
	}
      else if ((where = strstr (tool, lld_prefix)) != NULL)
	{
	  einfo (VERBOSE2, "ignoring linker version string found in .comment section");
	}
      else if (*tool)
	{
	  einfo (VERBOSE2, "unrecognised component in .comment section: %s", tool);
	}

      tool += strlen (tool) + 1;
    }

  return true;
}

static bool
check_sec (annocheck_data *     data,
	   annocheck_section *  sec)
{
  /* Note - the types checked here should correspond to the types
     selected in interesting_sec().  */
  switch (sec->shdr.sh_type)
    {
    case SHT_NOTE:     return check_note_section (data, sec);
    case SHT_STRTAB:   return check_string_section (data, sec);
    case SHT_DYNAMIC:  return check_dynamic_section (data, sec);
    case SHT_PROGBITS: return check_comment_section (data, sec);
    default:           return true;
    }
}

static bool
interesting_seg (annocheck_data *    data,
		 annocheck_segment * seg)
{
  if (disabled)
    return false;

  if ((seg->phdr->p_flags & (PF_X | PF_W | PF_R)) == (PF_X | PF_W | PF_R)
      && ! skip_check (TEST_RWX_SEG, NULL))
    {
      if (seg->phdr->p_type == PT_GNU_STACK)
	{
	  einfo (VERBOSE, "%s: FAIL: The GNU stack segment is executable\n",
		 data->filename);
	  tests[TEST_GNU_STACK].num_fail ++;
	}
      else
	{
	  einfo (VERBOSE, "%s: FAIL: seg %d has Read, Write and eXecute flags\n",
		 data->filename, seg->number);
	  tests[TEST_RWX_SEG].num_fail ++;
	}
    }

  switch (seg->phdr->p_type)
    {
    case PT_INTERP:
      tests[TEST_ENTRY].num_maybe ++;
      break;

    case PT_GNU_RELRO:
      tests[TEST_GNU_RELRO].num_pass ++;
      break;

    case PT_GNU_STACK:
      if ((seg->phdr->p_flags & (PF_W | PF_R)) != (PF_W | PF_R))
	{
	  einfo (VERBOSE, "%s: FAIL: The GNU stack segment does not have both read & write permissions\n",
		 data->filename);
	  tests[TEST_GNU_STACK].num_fail ++;
	}
      /* If the segment has the PF_X flag set it will have been reported as a failure above.  */
      else if ((seg->phdr->p_flags & PF_X) == 0)
	tests[TEST_GNU_STACK].num_pass ++;
      break;

    case PT_DYNAMIC:
      if (tests[TEST_DYNAMIC].num_pass < 2)
	/* 0 means it had no dynamic sections, 1 means it had a dynamic section.  */
	tests[TEST_DYNAMIC].num_pass = 2;
      else
	{
	  einfo (VERBOSE, "FAIL: %s: contains multiple dynamic segments.", data->filename);
	  tests[TEST_DYNAMIC].num_fail ++;
	}
      break;

    case PT_NOTE:
      if (skip_check (TEST_PROPERTY_NOTE, NULL))
	break;
      /* We want to examine the note segments on x86_64 binaries.  */
      return (per_file.e_machine == EM_X86_64);

    case PT_LOAD:
      /* If we are checking the entry point instruction then we need to load
	 the segment.  We check segments rather than sections because executables
	 do not have to have sections.  */
      if ((per_file.e_type == ET_EXEC || per_file.e_type == ET_DYN)
	  && (per_file.e_machine == EM_386 || per_file.e_machine == EM_X86_64)
	  && seg->phdr->p_memsz > 0
	  && seg->phdr->p_vaddr <= per_file.e_entry
	  && seg->phdr->p_vaddr + seg->phdr->p_memsz > per_file.e_entry
	  && ! skip_check (TEST_ENTRY, NULL))
	return true;
      break;

    default:
      break;
    }

  return false;
}

static bool
check_seg (annocheck_data *    data,
	   annocheck_segment * seg)
{
  if (seg->phdr->p_type == PT_LOAD)
    {
      Elf64_Addr entry_point = per_file.e_entry - seg->phdr->p_vaddr;

      /* We are checking the entry point instruction.  We should
	 only have reached this point if the requirements for the
	 check have already been met, so we do not need to test
	 them again.  */
      assert (entry_point + 3 < seg->data->d_size);
      memcpy (entry_bytes, seg->data->d_buf + entry_point, sizeof entry_bytes);
      
      if (per_file.e_machine == EM_386)
	{
	  /* Look for ENDBR32: 0xf3 0x0f 0x1e 0xfb. */
	  if (   entry_bytes[0] == 0xf3
	      && entry_bytes[1] == 0x0f
	      && entry_bytes[2] == 0x1e
	      && entry_bytes[3] == 0xfb)
	    tests[TEST_ENTRY].num_pass ++;
	  else
	    tests[TEST_ENTRY].num_fail ++;
	}
      else /* per_file.e_machine == EM_X86_64 */
	{
	  /* Look for ENDBR64: 0xf3 0x0f 0x1e 0xfa.  */
	  if (   entry_bytes[0] == 0xf3
	      && entry_bytes[1] == 0x0f
	      && entry_bytes[2] == 0x1e
	      && entry_bytes[3] == 0xfa)
	    tests[TEST_ENTRY].num_pass ++;
	  else
	    tests[TEST_ENTRY].num_fail ++;
	}

      return true;
    }

  if (per_file.e_machine != EM_X86_64)
    return true;

  /* FIXME: Only run these checks if the note section is missing ??  */

  GElf_Nhdr  note;
  size_t     name_off;
  size_t     data_off;
  size_t     offset = 0;

  offset = gelf_getnote (seg->data, offset, & note, & name_off, & data_off);

  if (seg->phdr->p_align != 8)
    {
      if (seg->phdr->p_align != 4)
	{
	  einfo (VERBOSE, "%s: warn: Note segment not 4 or 8 byte aligned (alignment: %ld)",
		 data->filename, (long) seg->phdr->p_align);
	  tests[TEST_PROPERTY_NOTE].num_fail ++;
	}

      if (note.n_type == NT_GNU_PROPERTY_TYPE_0)
	{
	  warn (data, "GNU Property note segment not 8 byte aligned");
	  tests[TEST_PROPERTY_NOTE].num_fail ++;
	}
    }

  if (note.n_type == NT_GNU_PROPERTY_TYPE_0)
    {
      if (offset != 0)
	{
	  warn (data, "More than one GNU Property note in note segment");
	  tests[TEST_PROPERTY_NOTE].num_fail ++;
	}
      else
	tests[TEST_PROPERTY_NOTE].num_pass ++;
    }

  return true;
}

typedef struct tool_id
{
  const char *  producer_string;
  enum tool     tool_type;
} tool_id;

static const tool_id tools[] =
{
 /* { "GNU C++", TOOL_GXX }, */
  { "GNU C", TOOL_GCC },
  { "GNU Fortran", TOOL_FORTRAN },
  { "rustc version", TOOL_RUST },
  { "clang version", TOOL_CLANG },
  { "clang LLVM", TOOL_CLANG }, /* Is this right ?  */
  { "GNU Fortran", TOOL_FORTRAN },
  { "Go cmd/compile", TOOL_GO },
  { "GNU AS", TOOL_GAS },
  { NULL, 0 }
};

/* Look for DW_AT_producer attributes.  */

static bool
hardened_dwarf_walker (annocheck_data * data, Dwarf * dwarf, Dwarf_Die * die, void * ptr ATTRIBUTE_UNUSED)
{
  Dwarf_Attribute  attr;
  const char *     string;

  if (dwarf_attr (die, DW_AT_producer, & attr) == NULL)
    return true;

  string = dwarf_formstring (& attr);
  if (string == NULL)
    {
      unsigned int form = dwarf_whatform (& attr);

      if (form == DW_FORM_GNU_strp_alt)
	warn (data, "DW_FORM_GNU_strp_alt not yet handled");
      else
	warn (data, "DWARF DW_AT_producer attribute uses non-string form");
      /* Keep scanning - there may be another DW_AT_producer attribute.  */
      return true;
    }

  einfo (VERBOSE2, "%s: DW_AT_producer = %s", data->filename, string);

  /* See if we can determine exactly which tool did produce this binary.  */
  const tool_id *  tool;
  const char *     where;
  enum tool        madeby = TOOL_UNKNOWN;
  unsigned int     version = 0;

  for (tool = tools; tool->producer_string != NULL; tool ++)
    if ((where = strstr (string, tool->producer_string)) != NULL)
      {
	madeby = tool->tool_type;
	/* Look for a space after the ID string.  */
	where = strchr (where + strlen (tool->producer_string), ' ');
	if (where != NULL)
	  version = strtod (where, NULL);
	break;
      }

  if (madeby == TOOL_UNKNOWN)
    {
      /* FIXME: This can happen for object files because the DWARF data
	 has not been relocated.  Find out how to handle this using libdwarf.  */
      if (per_file.e_type == ET_REL)
	warn (data, "DW_AT_producer string invalid - probably due to relocations not being applied");
      else
	warn (data, "Unable to determine the binary's producer from its DW_AT_producer string");
      /* Keep scanning.  */
      return true;
    }

  if (madeby != TOOL_GCC && per_file.tool == TOOL_UNKNOWN)
    info (data, "Discovered non-gcc code producer, skipping gcc specific checks");

  set_producer (data, madeby, version, "DW_AT_producer");

  /* The DW_AT_producer string may also contain some of the command
     line options that were used to compile the binary.  This happens
     when using the -grecord-gcc-switches option for example.  So we
     have an opportunity to check for producer-specific command line
     options.  Note - this is suboptimal since these options do not
     necessarily apply to the entire binary, but in the absence of
     annobin data they are better than nothing.  */
  switch (madeby)
    {
    default:
      break;
      
    case TOOL_CLANG:
      /* Try to determine if there are any command line options recorded in the
	 DW_AT_producer string.  FIXME: This is not a very good heuristic.  */
      if (strstr (string, "-f") || strstr (string, "-g") || strstr (string, "-O"))
	{
	  if (! skip_check (TEST_OPTIMIZATION, NULL))
	    {
	      if (strstr (string, " -O2") || strstr (string, " -O3"))
		{
		  tests[TEST_OPTIMIZATION].num_pass ++;
		  einfo (VERBOSE2, "%s: PASS: Compiled with sufficient optimization", data->filename);
		}
	      else if (strstr (string, " -O0") || strstr (string, " -O1"))
		{
		  /* FIXME: This may not be a failure.  GCC needs -O2 or
		     better for -D_FORTIFY_SOURCE to work properly, but
		     other compilers may not.  */
		  tests[TEST_OPTIMIZATION].num_fail ++;
		  einfo (VERBOSE, "%s: FAIL: Built with insufficient optimization", data->filename);
		}
	      else
		einfo (VERBOSE2, "%s: MAYB: Optimization level not found in DW_AT_producer string", data->filename);
	    }

	  if (! skip_check (TEST_PIC, NULL))
	    {
	      if (strstr (string, " -fpic") || strstr (string, " -fPIC")
		  || strstr (string, " -fpie") || strstr (string, " -fPIE"))
		{
		  tests[TEST_PIC].num_pass ++;
		  einfo (VERBOSE2, "%s: PASS: Compiled with -fpic/-fpie", data->filename);
		}
	      else
		einfo (VERBOSE2, "%s: MAYB: -fPIC/-fPIE not found in DW_AT_producer string", data->filename);
	    }

	  if (! skip_check (TEST_STACK_PROT, NULL))
	    {
	      if (strstr (string, "-fstack-protector-strong")
		  || strstr (string, "-fstack-protector-all"))
		{
		  tests[TEST_STACK_PROT].num_pass ++;
		  einfo (VERBOSE, "%s: PASS: Compiled with sufficient stack protection", data->filename);
		}
	      else if (strstr (string, "-fstack-protector"))
		{
		  tests[TEST_STACK_PROT].num_fail ++;
		  einfo (VERBOSE, "%s: FAIL: Compiled with insufficient stack protection", data->filename);
		}
	      else
		einfo (VERBOSE2, "%s: MAYB: -fstack-protector not found in DW_AT_producer string", data->filename);
	    }

	  if (! skip_check (TEST_WARNINGS, NULL))
	    {
	      if (strstr (string, "-Wall")
		  || strstr (string, "-Wformat-security")
		  || strstr (string, "-Werror=format-security"))
		{
		  tests[TEST_WARNINGS].num_pass ++;
		  einfo (VERBOSE, "%s: PASS: Compiled with sufficient warning enablement", data->filename);
		}
	      else
		einfo (VERBOSE2, "%s: MAYB: -Wall/-Wformat-security not found in DW_AT_producer string", data->filename);
	    }

	  if ((per_file.e_machine == EM_386 || per_file.e_machine == EM_X86_64)
	      && ! skip_check (TEST_CF_PROTECTION, NULL))
	    {
	      if (strstr (string, "-fcf-protection"))
		{
		  tests[TEST_CF_PROTECTION].num_pass ++;
		  einfo (VERBOSE, "%s: PASS: Compiled with control flow protection enabled", data->filename);
		}
	      else
		einfo (VERBOSE2, "%s: MAYB: -fcf-protection not found in DW_AT_producer string", data->filename);
	    }
	}
      else if (! per_file.warned_command_line)
	{
	  warn (data, "Command line options not recorded by -grecord-gcc-switches");
	  per_file.warned_command_line = true;
	}

      break;
    }

  /* Keep scanning - there may be another DW_AT_producer attribute.
     FIXME: This could take some time - is it worth it ?  */
  return true;
}

static void
fail (annocheck_data * data, const char * message)
{
  einfo (INFO, "%s: FAIL: %s", data->filename, message);
  ++ per_file.num_fails;
}

static void
maybe (annocheck_data * data, const char * message)
{
  einfo (INFO, "%s: MAYB: %s", data->filename, message);
  ++ per_file.num_maybes;
}

static void
pass (annocheck_data * data, const char * message)
{
  einfo (VERBOSE, "%s: PASS: %s", data->filename, message);
}

static void
skip (annocheck_data * data, const char * message)
{
  einfo (VERBOSE, "%s: skip: %s", data->filename, message);
}

/* Returns true if GAP is one that can be ignored.  */

static bool
ignore_gap (annocheck_data * data, hardened_note_data * gap)
{
  Elf_Scn * addr1_scn = NULL;
  Elf_Scn * addr2_scn = NULL;
  Elf_Scn * scn = NULL;
  ulong     scn_end = 0;
  ulong     scn_name = 0;

  /* These tests should be redundant, but just in case...  */
  if (ignore_gaps)
    return true;
  if (gap->start == gap->end)
    return true;
  if (gap->start > gap->end)
    {
      einfo (VERBOSE2, "gap ignored - start after end!");
      return true;
    }

  /* Gaps narrower than the alignment of the .text section are assumed
     to be padding between functions, and so can be ignored.  In theory
     there could be executable code in such gaps, and so we should also
     check that they are filled with NOP instructions.  But that is
     overkill at the moment.  Plus at the moment the default x86_64
     linker map does not appear to fill gaps with NOPs... */
  if ((gap->end - gap->start) < per_file.text_section_alignment)
    {
      einfo (VERBOSE2, "gap ignored - smaller than text section alignment");
      return true;
    }

  /* FIXME: The linker can create fill regions in the map that are larger
     than the text section alignment.  Not sure why, but it does happen.
     (cf lconvert in the qt5-qttools package which has a gap of 0x28 bytes
     between the end of .obj/main.o and the start of .obj/numerus.o).

     At the moment we have no way of determinining if a gap is because
     of linker filling or missing notes.  (Other than examining a linker
     map).  So we use a heuristic to allow for linker fill regions.
     0x2f is the largest such gap that I have seen so far...  */
  if ((gap->end - gap->start) <= 0x2f)
    {
      einfo (VERBOSE2, "gap ignored - probably linker padding");
      return true;
    }

  /* Find out where the gap starts and ends.  */
  if (data->is_32bit)
    {
      while ((scn = elf_nextscn (data->elf, scn)) != NULL)
	{
	  Elf32_Shdr * shdr = elf32_getshdr (scn);

	  if (addr1_scn == NULL
	      && shdr->sh_addr <= gap->start && ((shdr->sh_addr + shdr->sh_size) >= gap->start))
	    addr1_scn = scn;

	  if (addr2_scn == NULL)
	    {
	      scn_end = shdr->sh_addr + shdr->sh_size;
	      scn_name = shdr->sh_name;

	      if (shdr->sh_addr <= gap->end && scn_end >= gap->end)
		addr2_scn = scn;
	    }
	}
    }
  else
    {
      while ((scn = elf_nextscn (data->elf, scn)) != NULL)
	{
	  Elf64_Shdr * shdr = elf64_getshdr (scn);

	  if (addr1_scn == NULL
	      && shdr->sh_addr <= gap->start && ((shdr->sh_addr + shdr->sh_size) >= gap->start))
	    addr1_scn = scn;

	  if (addr2_scn == NULL)
	    {
	      scn_end = shdr->sh_addr + shdr->sh_size;
	      scn_name = shdr->sh_name;

	      if (shdr->sh_addr <= gap->end && scn_end >= gap->end)
		addr2_scn = scn;
	    }
	}
    }

  /* If the gap is not inside one or more sections, then something funny has gone on...  */
  if (addr2_scn == NULL)
    return false;

  /* If the gap starts in one section, but ends in a different section then we ignore it.  */
  if (addr1_scn != addr2_scn)
    {
      einfo (VERBOSE2, "gap ignored - crosses section boundary");
      return true;
    }

  /* On the PowerPC64, the linker can insert PLT resolver stubs at the end of the .text section.
     These will be unannotated, but they can safely be ignored.

     We may not have the symbol table available however so check to see if the gap ends at the
     end of the .text section.  */
  if (per_file.e_machine == EM_PPC64
      && align (gap->end, 8) == align (scn_end, 8)
      && scn_name == per_file.text_section_name_index)
    {
      const char * sym = annocheck_find_symbol_for_address_range (data, NULL, gap->start + 8, gap->end - 8, false);

      if (sym)
	{
	  if (strstr (sym, "glink_PLTresolve") || strstr (sym, "@plt"))
	    {
	      einfo (VERBOSE2, "Ignoring gap %lx..%lx at end of ppc64 .text section - it contains PLT stubs",
		     gap->start, gap->end);
	      return true;
	    }
	  else
	    einfo (VERBOSE2, "Potential PLT stub gap contains the symbol '%s', so the gap is not ignored", sym);
	}
      else
	{
	  /* Without symbol information we cannot be sure, but it is a reasonable supposition.  */
	  einfo (VERBOSE2, "Ignoring gap %lx..%lx at end of ppc64 .text section - it will contain PLT stubs",
		 gap->start, gap->end);
	  return true;
	}
    }

  return false;
}

static signed int
compare_range (const void * r1, const void * r2)
{
  hardened_note_data * n1 = (hardened_note_data *) r1;
  hardened_note_data * n2 = (hardened_note_data *) r2;

  if (n1->end < n2->start)
    return -1;

  if (n1->start > n2->end)
    return 1;

  /* Overlap - we should merge the two ranges.  */
  if (n1->start < n2->start)
    return -1;

  if (n1->end > n2->end)
    return 1;

  /* N1 is wholly covered by N2:
       n2->start <= n1->start <  n2->end
       n2->start <= n1->end   <= n2->end.
     We adjust its range so that the gap detection code does not get confused.  */
  n1->start = n2->start;
  n1->end   = n2->end;
  assert (n1->start < n1->end);
  return 0;
}

/* Certain symbols can indicate that a gap can be safely ignored.  */

static bool
skip_gap_sym (const char * sym)
{
  /* G++ will generate virtual and non-virtual thunk functions all on its own,
     without telling the annobin plugin about them.  Detect them here and do
     not complain about the gap in the coverage.  */
  if (const_strneq (sym, "_ZThn") || const_strneq (sym, "_ZTv0"))
    return true;

  /* If the symbol is for a function/file that we know has special
     reasons for not being proplerly annotated then we skip it.  */
  if (skip_check (TEST_MAX, sym))
    return true;

  if (per_file.e_machine == EM_386)
    {
      if (const_strneq (sym, "__x86.get_pc_thunk")
	  || const_strneq (sym, "_x86_indirect_thunk_"))
	return true;
    }
  else if (per_file.e_machine == EM_PPC64)
    {
      if (const_strneq (sym, "_savegpr")
	  || const_strneq (sym, "_restgpr")
	  || const_strneq (sym, "_savefpr")
	  || const_strneq (sym, "_restfpr")
	  || const_strneq (sym, "_savevr")
	  || const_strneq (sym, "_restvr"))
	return true;

      /* The linker can also generate long call stubs.  They have the form:
         NNNNNNNN.<stub_name>.<func_name>.  */
      const size_t len = strlen (sym);
      if (   (len > 8 + 10 && const_strneq (sym + 8, ".plt_call."))
	  || (len > 8 + 12 && const_strneq (sym + 8, ".plt_branch."))
	  || (len > 8 + 13 && const_strneq (sym + 8, ".long_branch.")))
	return true;

      /* The gdb server program contains special assembler stubs that
	 are unannotated.  See BZ 1630564 for more details.  */
      if (const_strneq (sym, "start_bcax_"))
	return true;
    }

  return false;
}

static void
check_for_gaps (annocheck_data * data)
{
  assert (! ignore_gaps);

  if (next_free_range < 2)
    return;

  /* Sort the ranges array.  */
  qsort (ranges, next_free_range, sizeof ranges[0], compare_range);

  hardened_note_data current = ranges[0];

  /* Scan the ranges array.  */
  bool gap_found = false;
  unsigned i;
  for (i = 1; i < next_free_range; i++)
    {
      if (ranges[i].start <= current.end)
	{
	  if (ranges[i].start < current.start)
	    current.start = ranges[i].start;

	  if (ranges[i].end > current.end)
	    /* ranges[i] overlaps current.  */
	    current.end = ranges[i].end;
	}
      else if (ranges[i].start <= align (current.end, 16))
	{
	  /* Append ranges[i].  */
	  assert (ranges[i].end >= current.end);
	  current.end = ranges[i].end;
	}
      else
	{
	  hardened_note_data gap;

	  gap.start = current.end;
	  gap.end   = ranges[i].start;

	  /* We have found a gap, so reset the current range.  */
	  current = ranges[i];

	  if (ignore_gap (data, & gap))
	    continue;

	  const char * sym = annocheck_find_symbol_for_address_range (data, NULL, gap.start, gap.end, false);
	  if (sym && skip_gap_sym (sym))
	    {
	      einfo (VERBOSE2, "gap ignored - special symbol: %s", sym);

	      /* FIXME: Really we should advance the gap start to the end of the address
		 range covered by the symbol and then check for gaps again.  But this will
		 probably causes us more problems than we want to handle right now.  */
	      continue;
	    }

	  /* If the start of the range was not aligned to a function boundary
	     then try again, this time with an aligned start symbol.
	     FIXME: 16 is suitable for x86_64, but not necessarily other architectures.  */
	  if (gap.start != align (gap.start, 16))
	    {
	      const char * sym2;

	      sym2 = annocheck_find_symbol_for_address_range (data, NULL, align (gap.start, 16), gap.end, false);
	      if (sym2 != NULL
		  && (sym == NULL || ! streq (sym, sym2))
		  && strstr (sym2, ".end") == NULL)
		{
		  if (skip_gap_sym (sym2))
		    {
		      einfo (VERBOSE2, "gap ignored - special symbol: %s", sym2);
		      /* See comment above.  */
		      continue;
		    }

		  gap.start = align (gap.start, 16);
		  sym = sym2;
		}
	    }

	  /* Finally, give it one more go, looking for a symbol half way through the gap.  */
	  if (gap.end - gap.start > 32)
	    {
	      const char * sym2;
	      ulong start = align (gap.start + (gap.end - gap.start) / 2, 32);

	      sym2 = annocheck_find_symbol_for_address_range (data, NULL, start, start + 32, false);

	      if (sym2 != NULL
		  && (sym == NULL || ! streq (sym, sym2))
		  && strstr (sym2, ".end") == NULL)
		{
		  if (skip_gap_sym (sym2))
		    {
		      einfo (VERBOSE2, "gap ignored - special symbol: %s", sym2);
		      /* See comment above.  */
		      continue;
		    }
		}
	    }
	      
	  gap_found = true;
	  if (! BE_VERBOSE)
	    break;

	  if (sym)
	    {
	      const char * cpsym = NULL;

	      if (sym[0] == '_' && sym[1] == 'Z')
		{
		  cpsym = cplus_demangle (sym, DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE);
		  if (cpsym != NULL)
		    sym = cpsym;
		}

	      einfo (VERBOSE, "%s: gap:  (%lx..%lx probable component: %s) in annobin notes",
		     data->filename, gap.start, gap.end, sym);

	      free ((char *) cpsym);
	    }
	  else
	    einfo (VERBOSE, "%s: gap:  (%lx..%lx) in annobin notes",
		   data->filename, gap.start, gap.end);
	}
    }

  if (! gap_found)
    pass (data, "No gaps found");
  else if (! BE_VERBOSE)
    fail (data, "Gaps were detected in the annobin coverage.  Run with -v to list");
  else
    fail (data, "Gaps were detected in the annobin coverage");
}

static void
show_BRANCH_PROTECTION  (annocheck_data * data, test * results)
{
  if (per_file.e_machine != EM_AARCH64)
    skip (data, "Branch protection.  (Not an AArch64 binary)");

  else if (! built_by_gcc ())
    skip (data, "Branch protection.  (Not built by gcc)");

  else if (per_file.version < 9)
    skip (data, "Branch protection.  (Needs gcc 9+)");

  else if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	{
	  if (BE_VERBOSE)
	    fail (data, "Parts of the binary were compiled without branch protection");
	  else
	    fail (data, "Parts of the binary were compiled without branch protection.  Run with -v to see where");
	}
      else
	fail (data, "The binary was compiled without -mbranch-protection");
    }
  else if (results->num_maybe > 0)
    {
      if (BE_VERBOSE)
	maybe (data, "Unknown string used with -mbranch-protection=");
      else
	maybe (data, "Unknown string used with -mbranch-protection=.  Run with -v to see where");
    }
  else if (results->num_pass > 0)
    {
      pass (data, "Compiled with -mbranch-protection");
    }
  else
    {
      /* FIXME: Only inform the user for now.  Once -mbranch-protection has
	 been added to the rpm macros then change this result to a maybe().  */
      /* maybe (data, "The -mbranch-protection setting was not recorded");  */
      info (data, "The -mbranch-protection setting was not recorded");
    }
}

static void
show_ENTRY (annocheck_data * data, test * results)
{
  if (per_file.e_machine != EM_386 && per_file.e_machine != EM_X86_64)
    skip (data, "Entry point instruction is ENDBR.  (Not an x86 binary)");
  else if (per_file.e_type != ET_DYN && per_file.e_type != ET_EXEC)
    skip (data, "Entry point instruction is ENDBR.  (Not a dynamic executable)");
  else if (results->num_maybe == 0) /* Ie there was no PT_INTERP segment.  */
    skip (data, "Entry point instruction is ENDBR.  (Not an executable)");
  else if (! per_file.compiled_code_seen)
    skip (data, "Entry point not ENDBR, but code not produced by a known compiler");
  else if (per_file.e_entry == 0)
    maybe (data, "Entry point address is zero");
  else if (results->num_fail > 0)
    {
      if (per_file.e_machine == EM_386)
	fail (data, "Entry point instruction is not ENDBR32");
      else
	fail (data, "Entry point instruction is not ENDBR64");

      if (BE_VERBOSE)
	einfo (VERBOSE, "%s:      (Entry Address: %#lx.  Bytes at this address: %x %x %x %x)",
	       data->filename, (long) per_file.e_entry,
	       entry_bytes[0], entry_bytes[1], entry_bytes[2], entry_bytes[3]);
    }
  else
    pass (data, "Entry point instruction is ENDBR");
}

static void
show_SHORT_ENUM (annocheck_data * data, test * results)
{
  if (results->num_fail > 0 && results->num_pass > 0)
    {
      if (BE_VERBOSE)
	fail (data, "Linked with different -fshort-enum settings");
      else
	fail (data, "Linked with different -fshort-enum settings.  Run with -v to see where");
    }
  else if (results->num_maybe > 0)
    maybe (data, "Corrupt notes on the -fshort-enum setting detected");
  else if (results->num_fail > 0 || results->num_pass > 0)
    pass (data, "Consistent use of the -fshort-enum option");
  else if (! built_by_gcc ())
    skip (data, "Test of enum size.  (Not built by gcc)");
  else
    /* Use SKIP rather than MAYBE here as this is not critical.  */
    skip (data, "No data about the use of -fshort-enum available");
}

static void
show_WARNINGS (annocheck_data * data, test * results)
{
  if (results->num_fail > 0)
    {
      if (BE_VERBOSE)
	fail (data, "Compiled without using either the -Wall or -Wformat-security options");
      else
	fail (data, "Compiled without using either the -Wall or -Wformat-security options. Run with -v to see where");
    }
  else if (results->num_maybe > 0)
    {
      maybe (data, "Corrupted warning data encountered");
    }
  else if (results->num_pass == 0)
    {
      if (! built_by_compiler ())
	skip (data, "Checking for warning options (not built by gcc");
      else
	maybe (data, "No data about compilation warnings found");
    }
  else
    pass (data, "Compiled with either -Wall and/or -Wformat-security");
}

static void
show_PROPERTY_NOTE (annocheck_data * data, test * results)
{
  if (per_file.e_machine != EM_X86_64)
    skip (data, "GNU Property note check.  (Only useful on x86_64 binaries)");

  else if (results->num_fail > 0)
    {
      if (BE_VERBOSE)
	fail (data, "Bad GNU Property note(s)");
      else
	fail (data, "Bad GNU Property note(s).  Run with -v to see what is wrong");
    }
  else if (results->num_maybe > 0)
    maybe (data, "Corrupt GNU Property note");
  else if (results->num_pass > 0)
    pass (data, "Good GNU Property note");
  else if (tests[TEST_CF_PROTECTION].enabled && tests[TEST_CF_PROTECTION].num_pass > 0)
    {
      if (! built_by_compiler ())
	skip (data, "Control flow protection is enabled, but some parts of the binary have been created by a tool other than GCC or CLANG, and so do not have the necessary markup.  This means that Intel's control flow protection technology (CET) will *not* be enabled for any part of the binary");
      else
	fail (data, "Control flow protection has been enabled for only some parts of the binary.  Other parts (probably assembler sources) are missing the protection, and without it global control flow protection cannot be enabled");
    }
  else
    pass (data, "GNU Property note not needed");
}

static void
show_BIND_NOW (annocheck_data * data, test * results)
{
  if (per_file.e_type != ET_EXEC && per_file.e_type != ET_DYN)
    skip (data, "Test for -Wl,-z,now.  (Only needed for executables)");
  else if (tests[TEST_DYNAMIC].num_pass == 0)
    skip (data, "Test for -Wl,-z,now.  (No dynamic segment present)");
  else if (results->num_maybe == 0)
    skip (data, "Test for -Wl,-z-now.  (Dynamic segment present, but no dynamic relocations found)");
  else if (per_file.tool == TOOL_GO)
    /* FIXME: This is for GO binaries.  Should be changed once GO supports PIE & BIND_NOW.  */
    skip (data, "Test for -Wl,-z,now.  (Binary was built by GO)");
  else if (built_by_mixed ())
    /* FIXME: Should be changed once GO supports PIE & BIND_NOW.  */
    skip (data, "Test for -Wl,-z,now.  (Binary was built by different compilers)");
  else if (results->num_pass == 0 || results->num_fail > 0)
    fail (data, "Not linked with -Wl,-z,now");
  else
    pass (data, "Linked with -Wl,-z,now");
}

static void
show_DYNAMIC (annocheck_data * data, test * results)
{
  if (results->num_fail > 0)
    fail (data, "Multiple dynamic sections/segments found");
  else if (results->num_pass == 0)
    pass (data, "No dynamic sections/segments found");
  else
    pass (data, "One dynamic section/segment found");
}

static void
show_GNU_RELRO (annocheck_data * data, test * results)
{
  /* Relocateable object files are not yet linked.  */
  if (per_file.e_type == ET_REL)
    skip (data, "Test for -Wl,-z,relro.  (Not needed in object files)");
  else if (tests[TEST_DYNAMIC].num_pass == 0)
    skip (data, "Test for -Wl,-z,relro.  (No dynamic segment present)");
  else if (tests [TEST_BIND_NOW].num_maybe == 0)
    skip (data, "Test for -Wl,-z,relro.  (No dynamic relocations)");
  else if (per_file.tool == TOOL_GO)
    /* FIXME: This is for GO binaries.  Should be changed once GO supports PIE & BIND_NOW.  */
    skip (data, "Test for -Wl,z,relro. (Built by GO)");
  else if (results->num_pass == 0 || results->num_fail > 0)
    fail (data, "Not linked with -Wl,-z,relro");
  else
    pass (data, "Linked with -Wl,-z,relro");
}

static void
show_GNU_STACK (annocheck_data * data, test * results)
{
  /* Relocateable object files do not have a stack segment.  */
  if (per_file.e_type == ET_REL)
    skip (data, "Test of stack segment.  (Object files do not have segments)");
  else if (results->num_fail > 0 || results->num_maybe > 0)
    fail (data, "The GNU stack segment has the wrong permissions");
  else if (results->num_pass > 1)
    maybe (data, "Multiple GNU stack segments found!");
  else if (results->num_pass == 1)
    pass (data, "Stack not executable");
  else
    pass (data, "No stack section found");
}

static void
show_RWX_SEG (annocheck_data * data, test * results)
{
  if (per_file.e_type == ET_REL)
    skip (data, "Check for RWX segments.  (Object files do not have segments)");
  else if (results->num_fail > 0 || results->num_maybe > 0)
    fail (data, "A segment with RWX permissions was found");
  else
    pass (data, "No RWX segments found");
}

static void
show_TEXTREL (annocheck_data * data, test * results)
{
  if (per_file.e_type == ET_REL)
    skip (data, "Object files are allowed text relocations");
  else if (results->num_fail > 0 || results->num_maybe > 0)
    fail (data, "Text relocations found");
  else
    pass (data, "No text relocations found");
}

static void
show_RUN_PATH (annocheck_data * data, test * results)
{
  if (per_file.e_type == ET_REL)
    skip (data, "Test of runpath.  (Object files do not have one)");
  else if (results->num_fail > 0 || results->num_maybe > 0)
    {
      if (BE_VERBOSE)
	fail (data, "DT_RPATH/DT_RUNPATH contains directories not starting with /usr");
      else
	fail (data, "DT_RPATH/DT_RUNPATH contains directories not starting with /usr.  Run with -v for details.");
    }
  else
    pass (data, "DT_RPATH/DT_RUNPATH absent or rooted at /usr");
}

static void
show_THREADS (annocheck_data * data, test * results)
{
  if (results->num_fail > 0 || results->num_maybe > 0)
    fail (data, "Thread cancellation not hardened.  (Compiled without -fexceptions)");
  else
    pass (data, "No thread cancellation problems");
}

static void
show_WRITEABLE_GOT (annocheck_data * data, test * results)
{
  if (per_file.e_type == ET_REL)
    skip (data, "Test for writeable GOT.  (Object files do not have a GOT)");
  else if (results->num_fail > 0 || results->num_maybe > 0)
    fail (data, "Relocations for the GOT/PLT sections are writeable");
  else
    pass (data, "GOT/PLT relocations are read only");
}

static void
show_OPTIMIZATION (annocheck_data * data, test * results)
{
  if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	{
	  if (BE_VERBOSE)
	    fail (data, "Parts of the binary were compiled without sufficient optimization");
	  else
	    fail (data, "Parts of the binary were compiled without sufficient optimization.  Run with -v to see where");
	}
      else
	fail (data, "The binary was compiled without sufficient optimization");
    }
  else if (results->num_maybe > 0)
    {
      if (results->num_pass > 0)
	{
	  if (! BE_VERBOSE)
	    maybe (data, "Some parts of the binary do not record their optimization setting.  Run with -v to see where");
	  else
	    maybe (data, "Some parts of the binary do not record their optimization setting");
	}
      else
	maybe (data, "The optimization setting was not recorded");
    }
  else if (results->num_pass > 0)
    {
      pass (data, "Compiled with sufficient optimization");
    }
  else if (! built_by_compiler ())
    {
      skip (data, "Test of optimization level.  (Not built by gcc/clang)");
    }
  else
    {
      maybe (data, "The optimization setting was not recorded");
    }
}

static void
show_PIC (annocheck_data * data, test * results)
{
  if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	{
	  if (BE_VERBOSE)
	    fail (data, "Parts of the binary were compiled without the proper PIC/PIE option");
	  else
	    fail (data, "Parts of the binary were compiled without the proper PIC/PIE option.  Run with -v to see where");
	}
      else
	fail (data, "The binary was compiled without -fPIC/-fPIE specified");
    }
  else if (results->num_maybe > 0)
    {
      if (results->num_pass > 0)
	{
	  if (! BE_VERBOSE)
	    maybe (data, "Some parts of the binary do not record the PIC/PIE setting.  Run with -v to see where");
	  else
	    maybe (data, "Some parts of the binary do not record the PIC/PIE setting");
	}
      else
	maybe (data, "The PIC/PIE setting was not recorded");
    }
  else if (results->num_pass > 0)
    {
      pass (data, "Compiled with PIC/PIE");
    }
  else if (! built_by_compiler ())
    {
      skip (data, "Test for PIC compilation.  (Not built by gcc/clang)");
    }
  else
    {
      maybe (data, "The PIC/PIE setting was not recorded");
    }
}

static void
show_PIE (annocheck_data * data, test * results)
{
  if (! built_by_compiler ())
    skip (data, "Test for -pie.  (Not built with gcc/clang)");

  else if (results->num_fail > 0)
    fail (data, "Not linked as a position independent executable (ie need to add '-pie' to link command line)");

  else /* Ignore maybe results - they should not happen.  */
    pass (data, "Compiled as a position independent binary");
}

static void
show_STACK_PROT (annocheck_data * data, test * results)
{
  if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	{
	  if (BE_VERBOSE)
	    fail (data, "Parts of the binary were compiled without a suffcient -fstack-protector setting");
	  else
	    fail (data, "Parts of the binary were compiled without a suffcient -fstack-protector setting.  Run with -v to see where");
	}
      else
	fail (data, "The binary was compiled without -fstack-protector-strong");
    }
  else if (results->num_maybe > 0)
    {
      if (results->num_pass > 0)
	{
	  if (! BE_VERBOSE)
	    maybe (data, "Some parts of the binary do not record the -fstack-protector setting.  Run with -v to see where");
	  else
	    maybe (data, "Some parts of the binary do not record the -fstack-protector setting");
	}
      else
	maybe (data, "The -fstack-protector setting was not recorded");
    }
  else if (results->num_pass > 0)
    {
      pass (data, "Compiled with sufficient stack protection");
    }
  else if (! built_by_compiler ())
    {
      skip (data, "Test for stack protection.  (Not built by gcc/clang)");
    }
  else
    {
      maybe (data, "The -fstack-protector setting was not recorded");
    }
}

static void
show_STACK_CLASH (annocheck_data * data, test * results)
{
  if (per_file.e_machine == EM_ARM)
    skip (data, "Test for stack clash support.  (Not enabled on the ARM)");

  else if (! built_by_gcc ())
    skip (data, "Test for stack clash support.  (Not built by gcc)");

  else if (per_file.version < 7)
    skip (data, "Test for stack clash support.  (Needs gcc 7+)");

  else if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	{
	  if (BE_VERBOSE)
	    fail (data, "Parts of the binary were compiled without stack clash protection");
	  else
	    fail (data, "Parts of the binary were compiled without stack clash protection.  Run with -v to see where");
	}
      else
	fail (data, "The binary was compiled without -fstack-clash-protection");
    }
  else if (results->num_maybe > 0)
    {
      if (results->num_pass > 0)
	{
	  if (! BE_VERBOSE)
	    maybe (data, "Some parts of the binary do not record -fstack-clash-protection.  Run with -v to see where");
	  else
	    maybe (data, "Some parts of the binary do not record -fstack-clash-protection");
	}
      else
	maybe (data, "The stack clash protection setting was not recorded");
    }

  else if (results->num_pass > 0)
    pass (data, "Compiled with -fstack-clash-protection");

  else if (per_file.compiled_code_seen)
    maybe (data, "The -fstack-clash-protection setting was not recorded");

  else
    skip (data, "Test for stack clash support.  (No GCC compiled object files)");
}

static void
show_FORTIFY (annocheck_data * data, test * results)
{
  if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	{
	  if (BE_VERBOSE)
	    fail (data, "Parts of the binary were compiled without -D_FORTIFY_SOURCE=2");
	  else
	    fail (data, "Parts of the binary were compiled without -D_FORTIFY_SOURCE=2.  Run with -v to see where");
	}
      else if (per_file.e_type == ET_REL)
	maybe (data, "Could not determine if -DFORTIFY_SOURCE=2 was used, but this may be because this is an object file compiled from a language that does not use C headers");
      else
	fail (data, "The binary was compiled without -DFORTIFY_SOURCE=2");      
    }

  else if (! built_by_compiler ())
    skip (data, "Test for -D_FORTIFY_SOURCE=2.  (Not built by gcc/clang)");

  else if (results->num_maybe > 0)
    {
      if (results->num_pass > 0)
	{
	  if (! BE_VERBOSE)
	    fail (data, "Some parts of the binary were not compiled with -D_FORTIFY_SOURCE=2.  Run with -v to see where");
	  else
	    fail (data, "Some parts of the binary were not compiled with -D_FORTIFY_SOURCE=2");
	}
      /* If we know that we have seen -D_GLIBCXX_ASSERTIONS then we
	 should also have seen -D_FORTIFY_SOURCE.  Hence its absence
	 is a failure.  */
      else if (tests[TEST_GLIBCXX_ASSERTIONS].num_pass > 0)
	fail (data, "The binary was compiled without -DFORTIFY_SOURCE=2 but with -D_GLIBCXX_ASSERTIONS");
      else if (per_file.e_type == ET_REL)
	maybe (data, "Could not determine if -DFORTIFY_SOURCE=2 was used, but this may be because this is an object file compiled from a language that does not use C headers");
      else
	maybe (data, "The -D_FORTIFY_SOURCE=2 option was not seen");
    }

  else if (results->num_pass > 0)
    pass (data, "Compiled with -D_FORTIFY_SOURCE=2");

  else if (per_file.compiled_code_seen)
    maybe (data, "The -D_FORTIFY_SOURCE=2 option was not seen");

  else
    skip (data, "Test for -D_FORTIFY_SOURCE.  (No GCC compiled object files)");
}

static void
show_CF_PROTECTION (annocheck_data * data, test * results)
{
  if (per_file.e_machine != EM_386 && per_file.e_machine != EM_X86_64)
    skip (data, "Test for control flow protection.  (Only supported on x86 binaries)");

  else if (! built_by_compiler ())
    skip (data, "Test for control flow protection.  (Not built by gcc/clang)");

  else if (built_by_gcc () && per_file.version < 8)
    skip (data, "Test for control flow protection.  (Needs gcc v8+)");

  else if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	{
	  if (BE_VERBOSE)
	    fail (data, "Parts of the binary were compiled without sufficient -fcf-protection");
	  else
	    fail (data, "Parts of the binary were compiled without sufficient -fcf-protection.  Run with -v to see where");
	}
      else
	fail (data, "The binary was compiled without sufficient -fcf-protection");
    }

  else if (results->num_maybe > 0)
    {
      if (results->num_pass > 0)
	{
	  if (! BE_VERBOSE)
	    maybe (data, "Some parts of the binary do not record whether -fcf-protection was used.  Run with -v to see where");
	  else
	    maybe (data, "Some parts of the binary do not record whether -fcf-protection was used");
	}
      else
	maybe (data, "The -fcf-protection option was not seen");
    }

  else if (results->num_pass > 0)
    pass (data, "Compiled with -fcf-protection");

  else
    maybe (data, "The -fcf-protection option was not seen");
}

static void
show_GLIBCXX_ASSERTIONS (annocheck_data * data, test * results)
{
  if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0 || ! built_by_compiler ())
	{
	  if (BE_VERBOSE)
	    fail (data, "Parts of the binary were compiled without -D_GLIBCXX_ASSRTIONS");
	  else
	    fail (data, "Parts of the binary were compiled without -D_GLIBCXX_ASSRTIONS.  Run with -v to see where");
	}
      else
	fail (data, "The binary was compiled without -D_GLIBCXX_ASSERTIONS");
    }

  else if (! built_by_compiler ())
    skip (data, "Test for -D_GLIBCXX_ASSERTONS.  (Not built by gcc/clang)");

  else if (results->num_maybe > 0)
    {
      if (results->num_pass > 0)
	{
	  if (! BE_VERBOSE)
	    maybe (data, "Some parts of the binary do not record whether -D_GLIBCXX_ASSERTIONS was used.  Run with -v to see where");
	  else
	    maybe (data, "Some parts of the binary do not record whether -D_GLIBCXX_ASSERTIONS was used");
	}
      /* If we know that we have seen -D_FORTIFY_SOURCE then we should also
	 have seen -D_GLIBCXX_ASSERTIONS.  Hence its absence is a failure.  */
      else if (tests[TEST_FORTIFY].num_pass > 0)
	{
	  fail (data, "The binary was compiled without -D_GLIBCXX_ASSERTIONS");
	}
      else
	maybe (data, "The -D_GLIBCXX_ASSERTIONS option was not seen");
    }

  else if (results->num_pass > 0)
    pass (data, "Compiled with -D_GLIBCXX_ASSERTIONS");

  else if (per_file.compiled_code_seen)
    maybe (data, "The -D_GLIBCXX_ASSERTIONS option was not seen");

  else
    skip (data, "The test for -D_GLIBCXX_ASSERTIONS.  (No compiled code seen)");
}

static void
show_STACK_REALIGN (annocheck_data * data, test * results)
{
  if (per_file.e_machine != EM_386)
    skip (data, "Test for stack realignment support.  (Only needed on i686 binaries)");

  else if (! built_by_gcc ())
    skip (data, "Test for stack realignment support.  (Not built by gcc)");

  else if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	{
	  if (BE_VERBOSE)
	    fail (data, "Parts of the binary were compiled without -mstack-realign");
	  else
	    fail (data, "Parts of the binary were compiled without -mstack-realign.  Run with -v to see where");
	}
      else
	fail (data, "The binary was compiled without -mstack-realign");
    }
  else if (results->num_maybe > 0)
    {
      if (results->num_pass > 0)
	{
	  if (! BE_VERBOSE)
	    maybe (data, "Some parts of the binary do not record whether -mstack_realign was used.  Run with -v to see where");
	  else
	    maybe (data, "Some parts of the binary do not record whether -mstack_realign was used");
	}
      else
	maybe (data, "The -mstack-realign option was not seen");
    }

  else if (results->num_pass > 0)
    pass (data, "Compiled with -mstack_realign");

  else
    maybe (data, "The -mstack-realign option was not seen");
}

static bool
finish (annocheck_data * data)
{
  if (disabled || per_file.debuginfo_file)
    return true;

  /* Check to see if something other than gcc produced parts
     of this binary.  */
  (void) annocheck_walk_dwarf (data, hardened_dwarf_walker, NULL);

  if (! per_file.build_notes_seen
      /* NB/ This code must happen after the call to annocheck_walk_dwarf()
	 as that function is responsible for following links to debuginfo
	 files.  */
      && data->dwarf_filename != NULL
      && data->dwarf_fd != data->fd)
    {
      struct checker hardened_notechecker =
	{
	 "Hardened",
	 NULL,  /* start_file */
	 interesting_note_sec,
	 check_note_section,
	 NULL, /* interesting_seg */
	 NULL, /* check_seg */
	 NULL, /* end_file */
	 NULL, /* process_arg */
	 NULL, /* usage */
	 NULL, /* version */
	 NULL, /* start_scan */
	 NULL, /* end_scan */
	 NULL, /* internal */
	};

      /* There is a separate debuginfo file.  Scan it to see if there are any notes that we can use.  */
      einfo (VERBOSE, "%s: info: Running subchecker on %s", data->filename, data->dwarf_filename);
      annocheck_process_extra_file (& hardened_notechecker, data->dwarf_filename, data->filename, data->dwarf_fd);
    }

  if (! per_file.build_notes_seen && per_file.compiled_code_seen)
    fail (data, "Build notes were not found for this executable");

  if (! ignore_gaps)
    {
      if (per_file.e_type == ET_REL)
	skip (data, "Not checking for gaps (object file)");
      else if (! built_by_compiler ())
	skip (data, "Not checking for gaps (non-gcc compiled binary)");
      else
	check_for_gaps (data);
    }

  int i;
  for (i = 0; i < TEST_MAX; i++)
    {
      if (tests[i].enabled)
	{
	  tests[i].show_result (data, tests + i);
	  einfo (VERBOSE2, " Use --skip-%s to disable this test", tests[i].name);
	}
      else
	einfo (VERBOSE, "%s: skip: %s", data->filename, tests[i].description);
    }

  if (per_file.num_fails > 0)
    return false;

  if (per_file.num_maybes > 0)
    return false; /* FIXME: Add an option to ignore MAYBE results ? */

  return einfo (INFO, "%s: PASS", data->filename);
}

static void
version (void)
{
  einfo (INFO, "Version 1.3");
}

static void
usage (void)
{
  einfo (INFO, "Hardening/Security checker.  By default all relevant tests are run.");
  einfo (INFO, "  To disable an individual test use the following options:");

  int i;
  for (i = 0; i < TEST_MAX; i++)
    einfo (INFO, "    --skip-%-19sDisables: %s", tests[i].name, tests[i].description);

  einfo (INFO, "  The tool will also report missing annobin data unless:");
  einfo (INFO, "    --ignore-gaps             Ignore missing annobin data");

  einfo (INFO, "  The tool is enabled by default.  This can be changed by:");
  einfo (INFO, "    --disable-hardened        Disables the hardening checker");
  einfo (INFO, "    --enable-hardened         Reenables the hardening checker");

  einfo (INFO, "  Still to do:");
  einfo (INFO, "    Add a machine readable output mode");
}

static bool
process_arg (const char * arg, const char ** argv, const uint argc, uint * next)
{
  if (const_strneq (arg, "--skip-"))
    {
      arg += 7;

      int i;
      for (i = 0; i < TEST_MAX; i++)
	{
	  if (streq (arg, tests[i].name))
	    {
	      tests[i].enabled = false;
	      return true;
	    }
	}

      return false;
    }

  if (streq (arg, "--enable-hardened"))
    {
      disabled = false;
      return true;
    }

  if (streq (arg, "--disable-hardened"))
    {
      disabled = true;
      return true;
    }

  if (streq (arg, "--ignore-gaps"))
    {
      ignore_gaps = true;
      return true;
    }

  return false;
}


struct checker hardened_checker =
{
  "Hardened",
  start,
  interesting_sec,
  check_sec,
  interesting_seg,
  check_seg,
  finish,
  process_arg,
  usage,
  version,
  NULL, /* start_scan */
  NULL, /* end_scan */
  NULL, /* internal */
};

static __attribute__((constructor)) void
register_checker (void) 
{
  if (! annocheck_add_checker (& hardened_checker, ANNOBIN_VERSION / 100))
    disabled = true;
}
