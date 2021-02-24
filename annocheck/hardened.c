/* Checks the hardened status of the given file.
   Copyright (c) 2018 - 2021 Red Hat.

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

#ifndef EM_AARCH64 /* RHEL-6 does not define EM_AARCh64.  */
#define EM_AARCH64	183	/* ARM 64-bit architecture */
#endif

#define HARDENED_CHECKER_NAME   "Hardened"

/* Predefined names for all of the sources of information scanned by this checker.  */
#define SOURCE_ANNOBIN_NOTES    "annobin notes"
#define SOURCE_DW_AT_LANGUAGE   "DW_AT_language string"
#define SOURCE_DW_AT_PRODUCER   "DW_AT_producer string"
#define SOURCE_DYNAMIC_SECTION  "dynamic section"
#define SOURCE_DYNAMIC_SEGMENT  "dynamic segment"
#define SOURCE_ELF_HEADER       "ELF header"
#define SOURCE_FINAL_SCAN       "final scan"
#define SOURCE_PROPERTY_NOTES   "property notes"
#define SOURCE_SECTION_HEADERS  "section headers"
#define SOURCE_SEGMENT_CONTENTS "segment contents"
#define SOURCE_SEGMENT_HEADERS  "segment headers"
#define SOURCE_STRING_SECTION   "string section"

typedef struct note_range
{
  ulong         start;
  ulong         end;
} note_range;

/* Set by the constructor.  */
static bool disabled = false;

/* Can be changed by a command line option.  */
static bool ignore_gaps = false;
static bool fixed_format_messages = false;

#define FIXED_FORMAT_STRING "%s: test: %s file: %s"

#define TOOL_UNKNOWN  	0
#define TOOL_CLANG	(1 << 0)
#define TOOL_FORTRAN	(1 << 1)
#define TOOL_GAS	(1 << 2)
#define TOOL_GCC	(1 << 3)
#define TOOL_GIMPLE	(1 << 4)
#define TOOL_GO		(1 << 5)
#define TOOL_LLVM	(1 << 6)
#define TOOL_RUST	(1 << 7)

enum lang
{
  LANG_UNKNOWN = 0,
  LANG_ASSEMBLER,
  LANG_C,
  LANG_CXX,
  LANG_GO,
  LANG_RUST,
  LANG_OTHER
};

enum short_enum_state
{
  SHORT_ENUM_STATE_UNSET = 0,
  SHORT_ENUM_STATE_SHORT,
  SHORT_ENUM_STATE_LONG
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
  note_range  text_section_range;

  bool        is_little_endian;
  bool        debuginfo_file;
  bool        build_notes_seen;
  int         num_fails;
  int         num_maybes;
  uint        anno_major;
  uint        anno_minor;
  uint        anno_rel;
  uint        run_major;
  uint        run_minor;
  uint        run_rel;

  uint          seen_tools;
  uint          tool_version;
  uint          current_tool;
  note_range    note_data;

  const char *  component_name;
  uint          component_type;

  enum short_enum_state short_enum_state;

  uint        note_source[256];

  enum lang   lang;

  bool        gcc_from_comment;
  bool        warned_asm_not_gcc;
  bool        warned_about_instrumentation;
  bool        warned_version_mismatch;
  bool        warned_command_line;
  bool        other_language;
  bool        also_written;
} per_file;

/* Extensible array of note ranges  */
static note_range *  ranges = NULL;
static uint                  num_allocated_ranges = 0;
static uint                  next_free_range = 0;
#define RANGE_ALLOC_DELTA    16

/* Array used to store instruction bytes at entry point.
   Use for verbose reporting when the ENTRY test fails.  */
static unsigned char entry_bytes[4];

/* This structure defines an individual test.
   There are two types of test.  One uses the annobin notes to check that the correct build time options were used.
   The other checks the properties of the binary itself.
   The former is dependent upon the tool(s) used to produce the binary and the source language(s) involved.
   The latter is independent of the tools, languages and notes.  */

enum test_state
{
  STATE_UNTESTED = 0,
  STATE_PASSED,
  STATE_FAILED,
  STATE_MAYBE
};

typedef struct test
{
  bool	            enabled;	  /* If false then do not run this test.  */
  bool              skipped;      /* True is a skip message has been issued for this test.  */
  bool              result_announced;
  enum test_state   state;
  const char *      name;	  /* Also used as part of the command line option to disable the test.  */
  const char *      description;  /* Used in the --help output to describe the test.  */
} test;

enum test_index
{
  TEST_NOTES = 0,
  
  TEST_BIND_NOW,
  TEST_BRANCH_PROTECTION,
  TEST_CF_PROTECTION,
  TEST_DYNAMIC_SEGMENT,
  TEST_DYNAMIC_TAGS,
  TEST_ENTRY,
  TEST_FORTIFY,
  TEST_GLIBCXX_ASSERTIONS,
  TEST_GNU_RELRO,
  TEST_GNU_STACK,
  TEST_GO_REVISION,
  TEST_LTO,
  TEST_ONLY_GO,
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

#define MIN_GO_REVISION 14
#define STR(a) #a
#define MIN_GO_REV_STR(a,b,c) a STR(b) c

#define TEST(name,upper,description) \
  [ TEST_##upper ] = { true, false, false, STATE_UNTESTED, #name, description }

/* Array of tests to run.  Default to enabling them all.
   The result field is initialised in the start() function.  */
static test tests [TEST_MAX] =
{
  TEST (notes,              NOTES,              "Annobin note coverage"),
  TEST (bind-now,           BIND_NOW,           "Linked with -Wl,-z,now"),
  TEST (branch-protection,  BRANCH_PROTECTION,  "Compiled with -mbranch-protection=bti (AArch64 only, gcc 9+ only"),
  TEST (cf-protection,      CF_PROTECTION,      "Compiled with -fcf-protection=all (x86 only, gcc 8+ only)"),
  TEST (dynamic-segment,    DYNAMIC_SEGMENT,    "There is at most one dynamic segment/section"),
  TEST (dynamic-tags,       DYNAMIC_TAGS,       "Dynamic tags for PAC & BTI present (AArch64 only)"),
  TEST (entry,              ENTRY,              "The first instruction is ENDBR (x86 only)"),
  TEST (fortify,            FORTIFY,            "Compiled with -D_FORTIFY_SOURCE=2"),
  TEST (glibcxx-assertions, GLIBCXX_ASSERTIONS, "Compiled with -D_GLIBCXX_ASSERTIONS"),
  TEST (gnu-relro,          GNU_RELRO,          "The relocations for the GOT are not writeable"),
  TEST (gnu-stack,          GNU_STACK,          "The stack is not executable"),
  TEST (go-revision,        GO_REVISION,        MIN_GO_REV_STR ("GO compiler revision >= ", MIN_GO_REVISION, " (go only)")),
  TEST (lto,                LTO,                "Compiled with -flto"),
  TEST (only-go,            ONLY_GO,            "GO is not mixed with other languages.  (go only, x86 only)"),
  TEST (optimization,       OPTIMIZATION,       "Compiled with at least -O2"),
  TEST (pic,                PIC,                "All binaries must be compiled with -fPIC or fPIE"),
  TEST (pie,                PIE,                "Executables need to be compiled with -fPIE"),
  TEST (property-note,      PROPERTY_NOTE,      "Correctly formatted GNU Property notes (x86_64, aarch64, PowerPC)"),
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

#ifdef DISABLE_FUTURE_FAIL
static bool report_future_fail = false;
#else
static bool report_future_fail = true;
#endif

static inline bool
is_C_compiler (uint tool)
{
  return (tool & (TOOL_GCC | TOOL_CLANG | TOOL_LLVM | TOOL_GIMPLE)) != 0;
}

static inline bool
includes_assembler (uint mask)
{
  return mask & TOOL_GAS;
}

static inline bool
includes_gcc (uint mask)
{
  return mask & TOOL_GCC;
}

static inline bool
includes_clang (uint mask)
{
  return mask & TOOL_CLANG;
}

static inline bool
includes_gimple (uint mask)
{
  return mask & TOOL_GIMPLE;
}

static void
warn (annocheck_data * data, const char * message)
{
  /* We use the VERBOSE setting rather than WARN because that way
     we not get a prefix.  */
  einfo (VERBOSE, "%s: WARN: %s", data->filename, message);
}

static inline bool
is_x86 (void)
{
  return per_file.e_machine == EM_386 || per_file.e_machine == EM_X86_64;
}

static inline bool
is_executable (void)
{
  return per_file.e_type == ET_EXEC || per_file.e_type == ET_DYN;
}

static bool
skip_check (enum test_index check)
{
  if (check < TEST_MAX && ! tests[check].enabled)
    return true;

  /* BZ 1923439: IFuncs are compiled without some of the security
     features because they execute in a special enviroment.  */
  if (ELF64_ST_TYPE (per_file.component_type) == STT_GNU_IFUNC)
    {
      switch (check)
	{
	case TEST_FORTIFY:
	case TEST_STACK_CLASH:
	case TEST_STACK_PROT:
	  einfo (VERBOSE2, "skipping test %s for ifunc at %#lx", tests[check].name, per_file.note_data.start);
	  return true;
	default:
	  break;
	}
    }

  const char * component_name = per_file.component_name;

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
    { "_dl_start", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
    { "_init", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
    { "_fini", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
    { "__libc_csu_init", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
    { "__libc_csu_fini", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
    { "__libc_init_first", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
    { "__libc_start_main", { TEST_STACK_PROT, TEST_STACK_CLASH, TEST_STACK_REALIGN, TEST_MAX } },
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

/* Ensure that NAME will not use more than one line.  */
static const char *
sanitize_filename (const char * name)
{
  const char * n;

  for (n = name; *n != 0; n++)
    if (iscntrl (*n))
      break;
  if (*n == 0)
    return name;

  char * new_name;
  char * p;

  p = new_name = xmalloc (strlen (name) + 1);

  for (n = name; *n != 0; n++)
    *p++ = iscntrl (*n) ? ' ' : *n;

  *p = 0;
  return new_name;  
}

static void
pass (annocheck_data * data, uint testnum, const char * source, const char * reason)
{
  assert (testnum < TEST_MAX);

  if (! tests[testnum].enabled)
    return;

  /* If we have already seen a FAIL then do not also report a PASS.  */
  if (tests[testnum].state == STATE_FAILED)
    return;

  if (tests[testnum].state == STATE_UNTESTED)
    tests[testnum].state = STATE_PASSED;

  if (tests[testnum].result_announced)
    return;

  tests[testnum].result_announced = true;

  if (fixed_format_messages)
    einfo (INFO, FIXED_FORMAT_STRING, "PASS", tests[testnum].name, sanitize_filename (data->filename));
  else
    {
      if (! BE_VERBOSE)
	return;

      einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, data->filename);
      einfo (PARTIAL, "PASS: %s test ", tests[testnum].name);
      if (reason)
	einfo (PARTIAL, "because %s ", reason);
      if (BE_VERY_VERBOSE)
	einfo (PARTIAL, " (source: %s)\n", source);
      else
	einfo (PARTIAL, "\n");
    }
}

static void
skip (annocheck_data * data, uint testnum, const char * source, const char * reason)
{
  assert (testnum < TEST_MAX);

  if (! tests[testnum].enabled)
    return;

  if (tests[testnum].state == STATE_UNTESTED)
    tests[testnum].state = STATE_MAYBE; /* FIXME - this is to stop final() from complaining that the test was not seen.  Maybe use a new state ?  */
  
  if (tests[testnum].skipped)
    return;
  
  tests[testnum].skipped = true;

  if (fixed_format_messages)
    return;

  if (! BE_VERBOSE)
    return;

  einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, data->filename);
  einfo (PARTIAL, "skip: %s test ", tests[testnum].name);
  if (reason)
    einfo (PARTIAL, "because %s ", reason);
  if (BE_VERY_VERBOSE)
    einfo (PARTIAL, " (source: %s)\n", source);
  else
    einfo (PARTIAL, "\n");
}

static void
fail (annocheck_data * data,
      uint             testnum,
      const char *     source,
      const char *     reason)
{
  assert (testnum < TEST_MAX);

  if (! tests[testnum].enabled)
    return;

  per_file.num_fails ++;

  if (fixed_format_messages)
    einfo (INFO, FIXED_FORMAT_STRING, "FAIL", tests[testnum].name, sanitize_filename (data->filename));
  else if (tests[testnum].state != STATE_FAILED || BE_VERBOSE)
    {
      einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, data->filename);
      einfo (PARTIAL, "FAIL: %s test ", tests[testnum].name);
      if (reason)
	einfo (PARTIAL, "because %s ", reason);

      const char * name = per_file.component_name;
      if (name && BE_VERBOSE)
	{
	  if (const_strneq (name, "component: "))
	    einfo (PARTIAL, "(function: %s) ", name + strlen ("component: "));
	  else
	    einfo (PARTIAL, "(%s) ", name);
	}
      if (BE_VERY_VERBOSE)
	einfo (PARTIAL, "(source: %s)\n", source);
      else
	einfo (PARTIAL, "\n");
    }

  tests[testnum].state = STATE_FAILED;
}

static void
maybe (annocheck_data * data,
       uint             testnum,
       const char *     source,
       const char *     reason)
{
  assert (testnum < TEST_MAX);

  if (! tests[testnum].enabled)
    return;

  per_file.num_maybes ++;

  if (fixed_format_messages)
    einfo (INFO, FIXED_FORMAT_STRING, "MAYB", tests[testnum].name, sanitize_filename (data->filename));
  else if (tests[testnum].state == STATE_UNTESTED || BE_VERBOSE)
    {
      einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, data->filename);
      einfo (PARTIAL, "MAYB: test: %s ", tests[testnum].name);
      if (reason)
	einfo (PARTIAL, "because %s ", reason);
      if (per_file.component_name)
	einfo (PARTIAL, "(function: %s) ", per_file.component_name);
      if (BE_VERY_VERBOSE)
	einfo (PARTIAL, " (source: %s)\n", source);
      else
	einfo (PARTIAL, "\n");
    }

  if (tests[testnum].state != STATE_FAILED)
    tests[testnum].state = STATE_MAYBE;
}

static void
info (annocheck_data * data, uint testnum, const char * source, const char * extra)
{
  assert (testnum < TEST_MAX);

  if (! tests[testnum].enabled)
    return;

  if (fixed_format_messages)
    return;

  einfo (VERBOSE2, "%s: info: %s %s (source %s)",
	 data->filename, tests[testnum].name, extra, source);
}

static const char *
get_lang_name (enum lang lang)
{
  switch (lang)
    {
    default:
    case LANG_UNKNOWN: return "unknown";
    case LANG_ASSEMBLER: return "Assembler";
    case LANG_C: return "C";
    case LANG_CXX: return "C++";
    case LANG_OTHER: return "other";
    case LANG_GO: return "GO";
    case LANG_RUST: return "Rust";
    }
}

static void
set_lang (annocheck_data *  data,
	  enum lang         lang,
	  const char *      source)
{
  if (per_file.lang == LANG_UNKNOWN)
    {
      einfo (VERBOSE2, "%s: info: written in %s (source: %s)",
	     data->filename, get_lang_name (lang), source);

      per_file.lang = lang;
    }
  else if (per_file.lang == lang)
    ;
  else
    {
      if (! per_file.also_written)
	{
	  einfo (VERBOSE, "%s: info: ALSO written in %s (source: %s)",
		 data->filename, get_lang_name (lang), source);
	  per_file.also_written = true;
	}

      if (is_x86 () && (lang == LANG_GO || per_file.lang == LANG_GO))
	{
	  /* FIXME: This FAIL is only true if CET is not enabled.  */
	  if (tests[TEST_ONLY_GO].state != STATE_FAILED)
	    fail (data, TEST_ONLY_GO, source, "combining GO and non-GO object files on x86 systems is not safe - it disables CET");
	}

      /* FIXME: What to do ?
	 For now we choose C++ if it is one of the languages, so that the GLIBXX_ASSERTIONS test is enabled.  */
      if (per_file.lang != LANG_CXX && lang == LANG_CXX)
	per_file.lang = lang;
    }
}

static const char *
get_tool_name (uint tool)
{
  switch (tool)
    {
    default:           return "<unrecognised>";
    case TOOL_UNKNOWN: return "<unknown>";
    case TOOL_CLANG:   return "Clang";
    case TOOL_FORTRAN: return "Fortran";
    case TOOL_GAS:     return "Gas";
    case TOOL_GCC:     return "GCC";
    case TOOL_GIMPLE:  return "Gimple";
    case TOOL_GO:      return "GO";
    case TOOL_LLVM:    return "LLVM";
    case TOOL_RUST:    return "Rust";
    }
}

#define COMMENT_SECTION "comment section"

static void
add_producer (annocheck_data *  data,
	      uint              tool,
	      uint              version,
	      const char *      source,
	      bool              update_current_tool)
{
  einfo (VERBOSE2, "%s: info: record producer: %s version: %u source: %s",
	 data->filename, get_tool_name (tool), version, source);

  if (tool == TOOL_GO)
    {
      if (version == 0)
	{
	  if (tests[TEST_GO_REVISION].enabled
	      && tests[TEST_GO_REVISION].state == STATE_UNTESTED)
	    maybe (data, TEST_GO_REVISION, source, "unknown revision of the GO compiler used");
	}
      else if (version < MIN_GO_REVISION)
	{
	  if (tests[TEST_GO_REVISION].enabled
	      && tests[TEST_GO_REVISION].state != STATE_FAILED)
	    {
	      fail (data, TEST_GO_REVISION, source, MIN_GO_REV_STR ("GO revision must be >= ", MIN_GO_REVISION, ""));
	      einfo (VERBOSE, "%s: info: GO compiler revision %u detected in %s",
		     data->filename, version, source);
	    }
	}
      else
	pass (data, TEST_GO_REVISION, source, "GO compiler revision is sufficient");
    }
  
  if (update_current_tool)
    {
      per_file.current_tool = tool;
      if (version)
	per_file.tool_version = version;
    }

  if (per_file.seen_tools == TOOL_UNKNOWN)
    {
      per_file.seen_tools = tool;
      per_file.tool_version = version;  /* FIXME: Keep track of version numbers on a per-tool basis.  */
      if (! fixed_format_messages)
	{
	  if (version)
	    einfo (VERBOSE, "%s: info: set binary producer to %s version %u", data->filename, get_tool_name (tool), version);
	  else
	    einfo (VERBOSE, "%s: info: set binary producer to %s", data->filename, get_tool_name (tool));
	}

      if (tool == TOOL_GCC) /* FIXME: Update this if glibc ever starts using clang.  */
	per_file.gcc_from_comment = streq (source, COMMENT_SECTION);      
    }
  else if (per_file.seen_tools & tool)
    {
      if (per_file.tool_version != version && version > 0)
	{
	  if (per_file.tool_version < version)
	    per_file.tool_version = version;
	}
    }
  else
    {
      per_file.seen_tools |= tool;

      /* See BZ 1906171.
	 Specifically glibc creates some object files by using GCC to assemble hand
	 written source code and adds the -Wa,--generate-missing-build-notes=yes
	 option so that there is a note to cover the binary.  Since gcc was involved
	 the .comment section will add_producer(GCC).  But since the code is in fact
	 assembler, the usual GCC command line options will not be present.  So when
	 we see this conflict we choose GAS.  */
      if (tool == TOOL_GCC) /* FIXME: Update this if glibc ever starts using clang.  */
	per_file.gcc_from_comment = streq (source, COMMENT_SECTION);
      else if (tool == TOOL_GAS && per_file.gcc_from_comment)
	{
	  if (! per_file.warned_asm_not_gcc)
	    {
	      if (! fixed_format_messages)
		einfo (VERBOSE, "%s: info: assembler built by GCC detected - treating as pure assembler",
		       data->filename);
	      per_file.warned_asm_not_gcc = true;
	    }

	  per_file.seen_tools &= ~ TOOL_GCC;
	}

      if (! fixed_format_messages)
	{
	  if (version)
	    einfo (VERBOSE, "%s: info: set binary producer to %s version %u", data->filename, get_tool_name (tool), version);
	  else
	    einfo (VERBOSE, "%s: info: set binary producer to %s", data->filename, get_tool_name (tool));
	}
    }
}

static void
parse_dw_at_language (annocheck_data * data, Dwarf_Attribute * attr)
{
  Dwarf_Word val;

  if (dwarf_formudata (attr, & val) != 0)
    {
      warn (data, "Unable to parse DW_AT_language attribute");
      return;
    }
  
  switch (val)
    {
    case DW_LANG_C89:
    case DW_LANG_C:
    case DW_LANG_C99:
    case DW_LANG_ObjC:
    case DW_LANG_C11:
      set_lang (data, LANG_C, SOURCE_DW_AT_LANGUAGE);
      break;

    case DW_LANG_C_plus_plus:
    case DW_LANG_ObjC_plus_plus:
    case DW_LANG_C_plus_plus_03:
    case DW_LANG_C_plus_plus_11:
    case DW_LANG_C_plus_plus_14:
      if (! fixed_format_messages)
	einfo (VERBOSE, "%s: info: Written in C++", data->filename);
      set_lang (data, LANG_CXX, SOURCE_DW_AT_LANGUAGE);
      break;

    case DW_LANG_Go:
      set_lang (data, LANG_GO, SOURCE_DW_AT_LANGUAGE);
      break;

    case DW_LANG_Rust:
      set_lang (data, LANG_RUST, SOURCE_DW_AT_LANGUAGE);
      break;

    case DW_LANG_lo_user + 1:
      /* Some of the GO runtime uses this value,  */
      set_lang (data, LANG_ASSEMBLER, SOURCE_DW_AT_LANGUAGE);
      break;
      
    default:
      if (! per_file.other_language)
	{
	  switch (val)
	    {
	    default:
	      einfo (VERBOSE, "%s: info: Written in a language other than C/C++/Go/Rust", data->filename);
	      einfo (VERBOSE2, "debugging: val = %#lx", (long) val);
	      break;
	    }
	  per_file.other_language = true;
	}
      set_lang (data, LANG_OTHER, SOURCE_DW_AT_LANGUAGE);
      break;
    }
}

typedef struct tool_id
{
  const char *  producer_string;
  uint          tool_type;
} tool_id;

static const tool_id tools[] =
{
  { "GNU C",          TOOL_GCC },
  { "GNU Fortran",    TOOL_FORTRAN },
  { "rustc version",  TOOL_RUST },
  { "clang version",  TOOL_CLANG },
  { "clang LLVM",     TOOL_CLANG }, /* Is this right ?  */
  { "GNU Fortran",    TOOL_FORTRAN },
  { "GNU GIMPLE",     TOOL_GIMPLE },
  { "Go cmd/compile", TOOL_GO },
  { "GNU AS",         TOOL_GAS },
  { NULL,             TOOL_UNKNOWN }
};

struct tool_string
{
  const char * lead_in;
  const char * tool_name;
  uint         tool_id;
};

static inline bool
is_object_file (void)
{
  return per_file.e_type == ET_REL;
}

static void
parse_dw_at_producer (annocheck_data * data, Dwarf_Attribute * attr)
{
  const char * string = dwarf_formstring (attr);

  if (string == NULL)
    {
      uint form = dwarf_whatform (attr);

      if (form == DW_FORM_GNU_strp_alt)
	warn (data, "DW_FORM_GNU_strp_alt not yet handled");
      else
	warn (data, "DWARF DW_AT_producer attribute uses non-string form");
      /* Keep scanning - there may be another DW_AT_producer attribute.  */
      return;
    }

  einfo (VERBOSE2, "%s: DW_AT_producer = %s", data->filename, string);

  /* See if we can determine exactly which tool did produce this binary.  */
  const tool_id *  tool;
  const char *     where;
  uint             madeby = TOOL_UNKNOWN;
  uint             version = 0;

  for (tool = tools; tool->producer_string != NULL; tool ++)
    if ((where = strstr (string, tool->producer_string)) != NULL)
      {
	madeby = tool->tool_type;

	/* Look for a space after the ID string.  */
	where = strchr (where + strlen (tool->producer_string), ' ');
	if (where != NULL)
	  {
	    version = strtod (where + 1, NULL);
	    /* Convert go1.14.13 into 14.
	       Note - strictly speaking 14 is the revision, not the version.
	       But the GO compiler is always version 1, and it is the
	       revision that matters as far as security features are concerened.  */
	    if (version == 0
		&& madeby == TOOL_GO
		&& strncmp (where + 1, "go1.", 4) == 0)
	      version = strtod (where + 5, NULL);
	  }

	break;
      }

  if (madeby == TOOL_UNKNOWN)
    {
      /* FIXME: This can happen for object files because the DWARF data
	 has not been relocated.  Find out how to handle this using libdwarf.  */
      if (is_object_file ())
	warn (data, "DW_AT_producer string invalid - probably due to relocations not being applied");
      else
	warn (data, "Unable to determine the binary's producer from its DW_AT_producer string");
      return;
    }

  add_producer (data, madeby, version, "DW_AT_producer", true);

  /* The DW_AT_producer string may also contain some of the command
     line options that were used to compile the binary.  This happens
     when using the -grecord-gcc-switches option for example.  So we
     have an opportunity to check for producer-specific command line
     options.  Note - this is suboptimal since these options do not
     necessarily apply to the entire binary, but in the absence of
     annobin data they are better than nothing.  */

  /* Try to determine if there are any command line options recorded in the
     DW_AT_producer string.  FIXME: This is not a very good heuristic.  */
  if (strstr (string, "-f") || strstr (string, "-g") || strstr (string, "-O"))
    {
      if (strstr (string, " -O2") || strstr (string, " -O3"))
	pass (data, TEST_OPTIMIZATION, SOURCE_DW_AT_PRODUCER, NULL);
      else if (strstr (string, " -O0") || strstr (string, " -O1"))
	/* FIXME: This may not be a failure.  GCC needs -O2 or
	   better for -D_FORTIFY_SOURCE to work properly, but
	   other compilers may not.  */
	fail (data, TEST_OPTIMIZATION, SOURCE_DW_AT_PRODUCER, "optimization level too low");
      else
	info (data, TEST_OPTIMIZATION, SOURCE_DW_AT_PRODUCER, "not found in string");

      if (strstr (string, " -fpic") || strstr (string, " -fPIC")
	  || strstr (string, " -fpie") || strstr (string, " -fPIE"))
	pass (data, TEST_PIC, SOURCE_DW_AT_PRODUCER, NULL);
      else
	info (data, TEST_PIC, SOURCE_DW_AT_PRODUCER, "-fpic/-fpie not found in string");

      if (strstr (string, "-fstack-protector-strong")
	  || strstr (string, "-fstack-protector-all"))
	pass (data, TEST_STACK_PROT, SOURCE_DW_AT_PRODUCER, NULL);
      else if (strstr (string, "-fstack-protector"))
	fail (data, TEST_STACK_PROT, SOURCE_DW_AT_PRODUCER, "insufficient protection enabled");
      else
	info (data, TEST_STACK_PROT, SOURCE_DW_AT_PRODUCER, "not found in string");

      if (strstr (string, "-Wall")
	  || strstr (string, "-Wformat-security")
	  || strstr (string, "-Werror=format-security"))
	pass (data, TEST_WARNINGS, SOURCE_DW_AT_PRODUCER, NULL);
      else
	info (data, TEST_WARNINGS, SOURCE_DW_AT_PRODUCER, "not found in string");

      if (is_x86 ())
	{
	  if (strstr (string, "-fcf-protection"))
	    pass (data, TEST_CF_PROTECTION, SOURCE_DW_AT_PRODUCER, NULL);
	  else
	    info (data, TEST_CF_PROTECTION, SOURCE_DW_AT_PRODUCER, "not found in string");
	}
    }
  else if (BE_VERBOSE && ! per_file.warned_command_line)
    {
      warn (data, "Command line options not recorded by -grecord-gcc-switches");
      per_file.warned_command_line = true;
    }
}

/* Look for DW_AT_producer and DW_AT_language attributes.  */

static bool
dwarf_attribute_checker (annocheck_data *  data,
			 Dwarf *           dwarf ATTRIBUTE_UNUSED,
			 Dwarf_Die *       die,
			 void *            ptr ATTRIBUTE_UNUSED)
{
  Dwarf_Attribute  attr;

  if (dwarf_attr (die, DW_AT_language, & attr) != NULL)
    parse_dw_at_language (data, & attr);
  
  if (dwarf_attr (die, DW_AT_producer, & attr) != NULL)
    parse_dw_at_producer (data, & attr);

  /* Keep scanning.  */
  return true;
}

static bool
start (annocheck_data * data)
{
  if (disabled)
    return false;

  /* (Re) Set the results for the tests.  */
  int i;

  for (i = 0; i < TEST_MAX; i++)
    {
      tests [i].state = STATE_UNTESTED;
      tests [i].result_announced = false;
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
  if (per_file.e_type == ET_EXEC)
    fail (data, TEST_PIE, SOURCE_ELF_HEADER, "not linked with -Wl,-pie");
  else
    pass (data, TEST_PIE, SOURCE_ELF_HEADER, NULL);
    
  /* Check to see if something other than gcc produced parts
     of this binary.  */
  (void) annocheck_walk_dwarf (data, dwarf_attribute_checker, NULL);

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

      per_file.text_section_name_index  = sec->shdr.sh_name;
      per_file.text_section_alignment   = sec->shdr.sh_addralign;
      per_file.text_section_range.start = sec->shdr.sh_addr;
      per_file.text_section_range.end   = sec->shdr.sh_addr + sec->shdr.sh_size;
      
      return false; /* We do not actually need to scan the contents of the .text section.  */
    }

  if (per_file.debuginfo_file)
    return false;

  /* If the file has a stack section then check its permissions.  */
  if (streq (sec->secname, ".stack"))
    {
      if ((sec->shdr.sh_flags & (SHF_WRITE | SHF_EXECINSTR)) != SHF_WRITE)
	fail (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, ".stack section has permissions other than just WRITE");
      else if (tests[TEST_GNU_STACK].state == STATE_PASSED)
	maybe (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, "multiple stack sections detected");
      else
	pass (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, NULL);

      return false;
    }

  /* Note the permissions on GOT/PLT relocation sections.  */
  if (streq  (sec->secname,    ".rel.got")
      || streq  (sec->secname, ".rela.got")
      || streq  (sec->secname, ".rel.plt")
      || streq  (sec->secname, ".rela.plt"))
    {
      if (sec->shdr.sh_flags & SHF_WRITE)
	{
	  if (is_object_file ())
	    skip (data, TEST_WRITEABLE_GOT, SOURCE_SECTION_HEADERS, "Object file");
	  else
	    fail (data, TEST_WRITEABLE_GOT, SOURCE_SECTION_HEADERS, NULL);
	}
      else
	pass (data, TEST_WRITEABLE_GOT, SOURCE_SECTION_HEADERS, NULL);
	
      return false;
    }

  if (sec->shdr.sh_size == 0)
    return false;

  if (streq (sec->secname, ".comment"))
    return true;

  if (streq (sec->secname, ".gnu.attributes"))
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

static void
get_component_name (annocheck_data *     data,
		    annocheck_section *  sec,
		    note_range *         note_data,
		    bool                 prefer_func_symbol)
{
  char *         buffer;
  const char *   sym;
  int            res;
  uint           type;

  sym = annocheck_get_symbol_name_and_type (data, sec, note_data->start, note_data->end, prefer_func_symbol, & type);

  if (sym == NULL)
    {
      if (note_data->start == note_data->end)
	res = asprintf (& buffer, "address: %#lx", note_data->start);
      else
	res = asprintf (& buffer, "addr range: %#lx..%#lx", note_data->start, note_data->end);
    }
  else
    res = asprintf (& buffer, "component: %s", sym);

  free ((char *) per_file.component_name);

  if (res > 0)
    {
      per_file.component_name = buffer;
      per_file.component_type = type;
    }
  else
    {
      per_file.component_name = NULL;
      per_file.component_type = 0;
    }
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

static ulong
get_4byte_value (const unsigned char * data)
{
  if (per_file.is_little_endian)
    return  data[0]
      | (((ulong) data[1]) << 8)
      | (((ulong) data[2]) << 16)
      | (((ulong) data[3]) << 24);
  else
    return data[3]
      | (((ulong) data[2]) << 8)
      | (((ulong) data[1]) << 16)
      | (((ulong) data[0]) << 24);
}

static void
report_note_producer (annocheck_data * data,
		      unsigned char    producer,
		      const char *     source,
		      uint             version)
{
  if (! BE_VERBOSE)
    return;

  if (per_file.note_source[producer] == version)
    return;

  per_file.note_source[producer] = version;

  if (fixed_format_messages)
    return;

  einfo (PARTIAL, "%s: %s: info: notes produced by %s plugin ",
	 HARDENED_CHECKER_NAME, data->filename, source);

  if (version == 0)
    einfo (PARTIAL, "(version unknown)\n");
  else if (version > 99 && version < 1000)
    einfo (PARTIAL, "version %u.%02u\n", version / 100, version % 100);
  else
    einfo (PARTIAL, "version %u\n", version);
}

static const char *
note_name (const char * attr)
{
  if (isprint (* attr))
    return attr;

  switch (* attr)
    {
    case GNU_BUILD_ATTRIBUTE_VERSION:    return "Version";
    case GNU_BUILD_ATTRIBUTE_TOOL:       return "Tool";
    case GNU_BUILD_ATTRIBUTE_RELRO:      return "Relro";
    case GNU_BUILD_ATTRIBUTE_ABI:        return "ABI";
    case GNU_BUILD_ATTRIBUTE_STACK_SIZE: return "StackSize";
    case GNU_BUILD_ATTRIBUTE_PIC:        return "PIC";
    case GNU_BUILD_ATTRIBUTE_STACK_PROT: return "StackProt";
    case GNU_BUILD_ATTRIBUTE_SHORT_ENUM: return "Enum";
    default:                             return "<UNKNOWN>";
    }

}

static bool
build_note_checker (annocheck_data *     data,
		    annocheck_section *  sec,
		    GElf_Nhdr *          note,
		    size_t               name_offset,
		    size_t               data_offset,
		    void *               ptr ATTRIBUTE_UNUSED)
{
  bool          prefer_func_name;
  note_range *  note_data;

  if (note->n_type    != NT_GNU_BUILD_ATTRIBUTE_OPEN
      && note->n_type != NT_GNU_BUILD_ATTRIBUTE_FUNC)
    {
      einfo (FAIL, "%s: Unrecognised annobin note type %d", data->filename, note->n_type);
      return false;
    }

  prefer_func_name = note->n_type == NT_GNU_BUILD_ATTRIBUTE_FUNC;
  note_data = & per_file.note_data;

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
	  start = get_4byte_value (descdata);
	  end   = get_4byte_value (descdata + 4);
	}
      else
	{
	  einfo (FAIL, "%s: Corrupt annobin note, desc size: %x",
		 data->filename, note->n_descsz);
	  return false;
	}

      if (start > end)
	{
	  if (per_file.e_machine == EM_PPC64 && (start - end) <= 4)
	    /* On the PPC64, start symbols are biased by 4, but end symbols are not...  */
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

      if (end == (ulong) -1)
	{
	  einfo (WARN, "%s: Corrupt annobin note : end address == -1", data->filename);
	  start = end;
	}

      if (! is_object_file () && ! ignore_gaps)
	{
	  /* Notes can occur in any order and may be spread across multiple note
	     sections.  So we record the range covered here and then check for
	     gaps once we have examined all of the notes.  */
	  record_range (start, end);
	}

      if (start != per_file.note_data.start
	  || end != per_file.note_data.end)
	{
	  /* The range has changed.  Check the old range.  If it was non-zero
	     in length then record the last known producer for code in that region.  */
	  if (per_file.note_data.start != per_file.note_data.end)
	    add_producer (data, per_file.current_tool, per_file.tool_version, SOURCE_ANNOBIN_NOTES, false);

	  /* Update the saved range.  */
	  per_file.note_data.start = start;
	  per_file.note_data.end = end;

	  /* If the new range is valid, get a component name for it.  */
	  if (start != end)
	    get_component_name (data, sec, note_data, prefer_func_name);
	}
    }

  const char *  namedata = sec->data->d_buf + name_offset;
  uint          pos = (namedata[0] == 'G' ? 3 : 1);
  char          attr_type = namedata[pos - 1];
  const char *  attr = namedata + pos;

  /* We skip notes with empty ranges unless we are dealing with unrelocated
     object files.  */
  if (! is_object_file ()
      && note_data->start == note_data->end)
    {
      einfo (VERBOSE2, "skip %s note for zero-length range at %#lx",
	     note_name (attr), note_data->start);
      return true;
    }

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

  einfo (VERBOSE2, "process %s note for range at %#lx..%#lx",
	 note_name (attr), note_data->start, note_data->end);
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
	einfo (INFO, "%s: WARN: This checker only supports version %d of the Watermark protocol.  The data in the notes uses version %d",
	       data->filename, SPEC_VERSION, * attr - '0');

      /* Check the note per_file.  */
      ++ attr;
      char producer = * attr;
      ++ attr;

      uint version = 0;
      if (* attr != 0)
	version = strtod (attr, NULL);

      const char * name;
      switch (producer)
	{
	case ANNOBIN_TOOL_ID_ASSEMBLER:
	  name = "assembler";
	  add_producer (data, TOOL_GAS, 2, SOURCE_ANNOBIN_NOTES, true);
	  break;

	case ANNOBIN_TOOL_ID_LINKER:
	  name = "linker";
	  break;

	case ANNOBIN_TOOL_ID_GCC_HOT:
	case ANNOBIN_TOOL_ID_GCC_COLD:
	case ANNOBIN_TOOL_ID_GCC_STARTUP:
	case ANNOBIN_TOOL_ID_GCC_EXIT:
	case ANNOBIN_TOOL_ID_GCC:
	  name = "gcc";
	  producer = ANNOBIN_TOOL_ID_GCC;
	  if (version > 99)
	    add_producer (data, TOOL_GCC, version / 100, SOURCE_ANNOBIN_NOTES, true);
	  else
	    add_producer (data, TOOL_GCC, 0, SOURCE_ANNOBIN_NOTES, true);
	  /* FIXME: Add code to check that the version of the
	     note producer is not greater than our version.  */
	  break;

	case ANNOBIN_TOOL_ID_GCC_LTO:
	  name = "lto";
	  if (version > 99)
	    add_producer (data, TOOL_GIMPLE, version / 100, SOURCE_ANNOBIN_NOTES, true);
	  else
	    add_producer (data, TOOL_GIMPLE, 0, SOURCE_ANNOBIN_NOTES, true);
	  break;

	case ANNOBIN_TOOL_ID_LLVM:
	  name = "LLVM";
	  if (version > 99)
	    add_producer (data, TOOL_LLVM, version / 100, SOURCE_ANNOBIN_NOTES, true);
	  else
	    add_producer (data, TOOL_LLVM, 0, SOURCE_ANNOBIN_NOTES, true);
	  break;

	case ANNOBIN_TOOL_ID_CLANG:
	  name = "Clang";
	  if (version > 99)
	    add_producer (data, TOOL_CLANG, version / 100, SOURCE_ANNOBIN_NOTES, true);
	  else
	    add_producer (data, TOOL_CLANG, 0, SOURCE_ANNOBIN_NOTES, true);
	  break;

	default:
	  warn (data, "Unrecognised annobin note producer");
	  name = "unknown";
	  break;
	}

      report_note_producer (data, producer, name, version);
      break;

    case GNU_BUILD_ATTRIBUTE_TOOL:
      if (value != -1)
	{
	  einfo (VERBOSE, "ICE:  The tool note should have a string attribute");
	  break;
	}

      /* Parse the tool attribute looking for the version of gcc used to build the component.  */
      uint major, minor, rel;

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

	  einfo (VERBOSE2, "%s: info: detected information created by an annobin plugin running on %s version %u.%u.%u",
		 data->filename, t->tool_name, major, minor, rel);

	  /* Make a note of the producer in case there has not been any version notes.  */
	  if (t->tool_id != TOOL_GCC || per_file.current_tool != TOOL_GIMPLE)
	    add_producer (data, t->tool_id, major, SOURCE_ANNOBIN_NOTES, true);

	  if (per_file.run_major == 0)
	    {
	      per_file.run_major = major;
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
		  einfo (INFO, "%s: WARN: Annobin plugin was built by %s version %u but run on %s version %u",
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

	  einfo (VERBOSE2, "%s: info: detected information stored by an annobin plugin built by %s version %u.%u.%u",
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
		  einfo (INFO, "%s: WARN: Annobin plugin was built by %s version %u but run on %s version %u",
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
	  uint version = (uint) strtoul (gcc + 4, NULL, 10);

	  einfo (VERBOSE2, "%s: (%s) built-by gcc version %u",
		 data->filename, per_file.component_name, version);
	}
      else
	einfo (VERBOSE, "%s: (%s) unable to parse tool attribute: %s",
	       data->filename, per_file.component_name, attr);
      break;

    case GNU_BUILD_ATTRIBUTE_PIC:
      if (skip_check (TEST_PIC))
	break;

      /* Convert the pic value into a pass/fail result.  */
      switch (value)
	{
	case -1:
	default:
	  maybe (data, TEST_PIC, SOURCE_ANNOBIN_NOTES, "unexpected value");
	  einfo (VERBOSE2, "debug: PIC note value: %x", value);
	  break;

	case 0:
	  fail (data, TEST_PIC, SOURCE_ANNOBIN_NOTES, "-fpic/-fpie not enabled");
	  break;

	case 1:
	case 2:
	  /* Compiled wth -fpic not -fpie.  */
	  pass (data, TEST_PIC, SOURCE_ANNOBIN_NOTES, NULL);
	  break;

	case 3:
	case 4:
	  pass (data, TEST_PIC, SOURCE_ANNOBIN_NOTES, NULL);
	  break;
	}
      break;

    case GNU_BUILD_ATTRIBUTE_STACK_PROT:
      if (skip_check (TEST_STACK_PROT))
	break;

      /* We can get stack protection notes without tool notes.  See BZ 1703788 for an example.  */
      if (per_file.current_tool == TOOL_GO)
	{
	  skip (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "GO code does not support stack protection");
	  break;
	}

      switch (value)
	{
	case -1:
	default:
	  maybe (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	  break;

	case 0: /* NONE */
	  fail (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "no protection enabled");
	  break;

	case 1: /* BASIC (funcs using alloca or with local buffers > 8 bytes) */
	case 4: /* EXPLICIT */
	  fail (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "only some functions protected");
	  break;

	case 2: /* ALL */
	case 3: /* STRONG */
	  pass (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, NULL);
	  break;
	}
      break;

    case GNU_BUILD_ATTRIBUTE_SHORT_ENUM:
      {
	enum short_enum_state state = value ? SHORT_ENUM_STATE_SHORT : SHORT_ENUM_STATE_LONG;

	if (value < 0 || value > 1)
	  {
	    maybe (data, TEST_SHORT_ENUM, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	    einfo (VERBOSE2, "debug: enum note value: %x", value);
	  }
	else if (per_file.short_enum_state == SHORT_ENUM_STATE_UNSET)
	  per_file.short_enum_state = state;
	else if (per_file.short_enum_state != state)
	  fail (data, TEST_SHORT_ENUM, SOURCE_ANNOBIN_NOTES, "both short and long enums supported");
      }
      break;

    case 'b':
      if (const_strneq (attr, "branch_protection:"))
	{
	  if (per_file.e_machine != EM_AARCH64)
	    break;

	  if (skip_check (TEST_BRANCH_PROTECTION))
	    break;

	  attr += strlen ("branch_protection:");
	  if (* attr == 0
	      || streq (attr, "(null)")
	      || streq (attr, "default"))
	    /* FIXME: Turn into a FAIL once -mbranch-protection is required by the security spec.  */
	    info (data, TEST_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, "not enabled");
	  else if (streq (attr, "bti+pac-ret")
		   || (streq (attr, "standard"))
		   || const_strneq (attr, "pac-ret+bti"))
	    pass (data, TEST_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, NULL);
	  else if (streq (attr, "bti")
		   || const_strneq (attr, "pac-ret"))
	    fail (data, TEST_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, "only partially enabled");
	  else if (streq (attr, "none"))
	    fail (data, TEST_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, "protection disabled");
	  else
	    {
	      maybe (data, TEST_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: stack prot note value: %s", attr);
	    }
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case 'c':
      if (streq (attr, "cf_protection"))
	{
	  if (! is_x86 ())
	    break;

	  if (skip_check (TEST_CF_PROTECTION))
	    break;
	  
	  if (! is_C_compiler (per_file.current_tool))
	    {
	      skip (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "not built by gcc/clang");
	      break;
	    }

	  if (includes_gcc (per_file.current_tool) && per_file.tool_version < 8)
	    {
	      skip (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "needs gcc v8+");
	      break;
	    }

	  /* Note - the annobin plugin adds one to the value of gcc's flag_cf_protection,
	     thus a setting of CF_FULL (3) is actually recorded as 4, and so on.  */
	  switch (value)
	    {
	    case -1:
	    default:
	      maybe (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: cf prot note value: %x", value);
	      break;

	    case 4: /* CF_FULL.  */
	    case 8: /* CF_FULL | CF_SET */
	      pass (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, NULL);
	      break;

	    case 2: /* CF_BRANCH: Branch but not return.  */
	    case 6: /* CF_BRANCH | CF_SET */
	      fail (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "only branch protection enabled");
	      break;

	    case 3: /* CF_RETURN: Return but not branch.  */
	    case 7: /* CF_RETURN | CF_SET */
	      fail (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "only return protection enabled");
	      break;

	    case 1: /* CF_NONE: No protection. */
	    case 5: /* CF_NONE | CF_SET */
	      fail (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "no protection enabled");
	      break;
	    }
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case 'F':
      if (streq (attr, "FORTIFY"))
	{
	  if (skip_check (TEST_FORTIFY))
	    break;

	  if (! is_C_compiler (per_file.current_tool))
	    {
	      skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "not built by gcc/clang");
	      break;
	    }
	    
	  switch (value)
	    {
	    case -1:
	    default:
	      maybe (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: fortify note value: %x", value);
	      break;

	    case 0xfe:
	      /* Note - in theory this should be a MAYBE result because we do not
		 know the fortify level that was used when the original sources were
		 compiled.  But in practice doing this would generate MAYBE results
		 for all code compiled with -flto, even if -D_FORTIFY_SOURCE=2 was
		 used, and this would annoy a lot of users.  (Especially since
		 LTO and FORTIFY are now enabled by the rpm build macros).  So we
		 SKIP this test instead.
		 
		 In theory we could search to see if un-fortified versions of specific
		 functions are present in the executable's symbol table.  eg memcpy
		 instead of memcpy_chk.  This would help catch some cases where the
		 correct FORTIFY level was not set, but it would not work for test
		 cases which are intended to verify annocheck's ability to detect
		 this problem, but which do not call any sensitive functions.  (This
		 is done by QE).  It also fails for code which cannot be protected
		 by FORTIFY_SOURCE.  Such code will still use the unenhanced functions
		 but could well have been compiled with -D_FORTIFY_SOURCE=2.

		 Note - the annobin plugin for GCC will generate a compile time
		 warning if -D_FORTIFY_SOURCE is undefined or set to 0 or 1, but
		 only when compiling with -flto enabled, and not when compiling
		 pre-processed sources.  */
	      skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "LTO compilation discards preprocessor options");
	      break;

	    case 0xff:
	      if (per_file.current_tool == TOOL_GIMPLE)
		skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "LTO compilation discards preprocessor options");
	      else
		fail (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "-D_FORTIFY_SOURCE=2 was not present on command line");
	      break;

	    case 0:
	    case 1:
	      fail (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "-O level is too low");
	      break;

	    case 2:
	    case 3:
	      pass (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, NULL);
	      break;
	    }
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case 'G':
      if (streq (attr, "GOW"))
	{
	  if (value == -1)
	    {
	      maybe (data, TEST_OPTIMIZATION, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: optimization note value: %x", value);
	      break;
	    }

	  
	  if (skip_check (TEST_OPTIMIZATION))
	    ;
	  else if (value & (1 << 13))
	    {
	      /* Compiled with -Og rather than -O2.
		 Treat this as a flag to indicate that the package developer is
		 intentionally not compiling with -O2, so suppress warnings about it.  */
	      skip (data, TEST_OPTIMIZATION, SOURCE_ANNOBIN_NOTES, "Compiled with -Og");

	      /* Add a pass result so that we do not complain about lack of optimization information.  */
	      if (tests[TEST_OPTIMIZATION].state == STATE_UNTESTED)
		tests[TEST_OPTIMIZATION].state = STATE_PASSED;
	    }
	  else
	    {
	      uint opt = (value >> 9) & 3;

	      if (opt == 0 || opt == 1)
		fail (data, TEST_OPTIMIZATION, SOURCE_ANNOBIN_NOTES, "level too low");
	      else /* opt == 2 || opt == 3 */
		pass (data, TEST_OPTIMIZATION, SOURCE_ANNOBIN_NOTES, NULL);
	    }

	  
	  if (skip_check (TEST_WARNINGS))
	    ;
	  else if (value & (1 << 14))
	    {
	      /* Compiled with -Wall.  */
	      pass (data, TEST_WARNINGS, SOURCE_ANNOBIN_NOTES, NULL);
	    }
	  else if (value & (1 << 15))
	    {
	      /* Compiled with -Wformat-security but not -Wall.
		 FIXME: We allow this for now, but really would should check for
		 any warnings enabled by -Wall that are important.  (Missing -Wall
		 itself is not bad - this happens with LTO compilation - but we
		 still want important warnings enabled).  */
	      pass (data, TEST_WARNINGS, SOURCE_ANNOBIN_NOTES, NULL);
	    }
	  /* FIXME: At the moment the clang plugin is unable to detect -Wall.
	     for clang v9+.  */
	  else if (per_file.current_tool == TOOL_CLANG && per_file.tool_version > 8)
	    skip (data, TEST_WARNINGS, SOURCE_ANNOBIN_NOTES, "Warning setting not detectable in newer versions of Clang");
	  /* Gimple compilation discards warnings.  */
	  else if (per_file.current_tool == TOOL_GIMPLE)
	    skip (data, TEST_WARNINGS, SOURCE_ANNOBIN_NOTES, "LTO compilation discards preprocessor options");
	  else if (value & ((1 << 16) | (1 << 17)))
	    {
	      /* LTO compilation.  Normally caught by the GIMPLE test
		 above, but that does not work on stripped binaries.
		 We set STATE_PASSED here so that show_WARNINGS does
		 not complain about not finding any information.  */
	      if (tests[TEST_WARNINGS].state == STATE_UNTESTED)
		tests[TEST_WARNINGS].state = STATE_PASSED;
	    }
	  else
	    fail (data, TEST_WARNINGS, SOURCE_ANNOBIN_NOTES, "compiled without either -Wall or -Wformat-security");

	  
	  if (skip_check (TEST_LTO))
	    ;
	  else if (value & (1 << 16))
	    {
	      if (value & (1 << 17))
		fail (data, TEST_LTO, SOURCE_ANNOBIN_NOTES, "compiled with both -flto and -fno-lto");
	      else
		pass (data, TEST_LTO, SOURCE_ANNOBIN_NOTES, NULL);
	    }
	  else if (value & (1 << 17))
	    {
	      /* Compiled without -flto.
		 Not a failure because we are still bringing up universal LTO enabledment.  */
	      if (report_future_fail)
		info (data, TEST_LTO, SOURCE_ANNOBIN_NOTES, "compiled without -flto");
	    }
	  else
	    {
	      info (data, TEST_LTO, SOURCE_ANNOBIN_NOTES, " -flto status not recorded in notes");
	    }

	  break;
	}
      else if (streq (attr, "GLIBCXX_ASSERTIONS"))
	{
	  if (skip_check (TEST_GLIBCXX_ASSERTIONS))
	    break;

	  if (per_file.lang != LANG_UNKNOWN && per_file.lang != LANG_CXX)
	    {
	      skip (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_NOTES, "source language not C++");
	      break;
	    }
	  
	  if (! is_C_compiler (per_file.current_tool))
	    {
	      skip (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_NOTES, "current tool not gcc/clang");
	      break;
	    }

	  switch (value)
	    {
	    case 0:
	      if (per_file.current_tool == TOOL_GIMPLE)
		skip (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_NOTES, "LTO compilation discards preprocessor options");
	      else
		fail (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_NOTES, "compiled without -D_GLIBCXX_ASSERTIONS");
	      break;

	    case 1:
	      pass (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_NOTES, NULL);
	      break;

	    default:
	      maybe (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: assertion note value: %x", value);
	      break;
	    }
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case 'I':
      if (const_strneq (attr, "INSTRUMENT:"))
	{
	  if (! per_file.warned_about_instrumentation)
	    {
	      einfo (INFO, "%s: WARN: (%s): Instrumentation enabled - this is probably a mistake for production binaries",
		     data->filename, per_file.component_name);

	      per_file.warned_about_instrumentation = true;

	      if (BE_VERBOSE)
		{
		  uint sanitize, instrument, profile, arcs;

		  attr += strlen ("INSTRUMENT:");
		  if (sscanf (attr, "%u/%u/%u/%u", & sanitize, & instrument, & profile, & arcs) != 4)
		    {
		      einfo (VERBOSE2, "%s: ICE:  (%s): Unable to extract details from instrumentation note",
			     data->filename, per_file.component_name);
		    }
		  else
		    {
		      einfo (VERBOSE, "%s: info: (%s):  Details: -fsanitize=...: %s",
			     data->filename, per_file.component_name, sanitize ? "enabled" : "disabled");
		      einfo (VERBOSE, "%s: info: (%s):  Details: -finstrument-functions: %s",
			     data->filename, per_file.component_name, instrument ? "enabled" : "disabled");
		      einfo (VERBOSE, "%s: info: (%s):  Details: -p and/or -pg: %s",
			     data->filename, per_file.component_name, profile ? "enabled" : "disabled");
		      einfo (VERBOSE, "%s: info: (%s):  Details: -fprofile-arcs: %s",
			     data->filename, per_file.component_name, arcs ? "enabled" : "disabled");
		    }
		}
	      else
		einfo (INFO, "%s: info: (%s):  Run with -v for more information",
		       data->filename, per_file.component_name);
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

	  if (skip_check (TEST_STACK_CLASH))
	    break;

	  if (! includes_gcc (per_file.current_tool) && ! includes_gimple (per_file.current_tool))
	    {
	      skip (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, "not compiled by gcc");
	      break;
	    }
	  
	  if (per_file.tool_version < 7)
	    {
	      skip (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, "needs gcc 7+");
	      break;
	    }

	  switch (value)
	    {
	    case 0:
	      fail (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, "-fstack-clash-protection not enabled");
	      break;

	    case 1:
	      pass (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, NULL);
	      break;

	    default:
	      maybe (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: stack clash note vbalue: %x", value);
	      break;
	    }
	}
      else if (streq (attr, "stack_realign"))
	{
	  if (per_file.e_machine != EM_386)
	    break;

	  if (skip_check (TEST_STACK_REALIGN))
	    break;

	  if (! includes_gcc (per_file.current_tool) && ! includes_gimple (per_file.current_tool))
	    {
	      skip (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_NOTES, "Not built by gcc");
	      break;
	    }

	  switch (value)
	    {
	    default:
	      maybe (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: stack realign note vbalue: %x", value);
	      break;

	    case 0:
	      fail (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_NOTES, "-fstack-realign not enabled");
	      break;

	    case 1:
	      pass (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_NOTES, NULL);
	      break;
	    }
	}
      else if (streq (attr, "sanitize_cfi"))
	{
	  if (skip_check (TEST_CF_PROTECTION))
	    ;
	  else if (! includes_clang (per_file.current_tool))
	    skip (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "not built by clang");
	  else if (value < 1)
	    fail (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "insufficient Control Flow sanitization");
	  else /* FIXME: Should we check that specific sanitizations are enabled ?  */
	    pass (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, NULL);
	  break;
	}
      else if (streq (attr, "sanitize_safe_stack"))
	{
	  if (skip_check (TEST_STACK_PROT))
	    ;
	  else if (! includes_clang (per_file.current_tool))
	    skip (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "not built by clang");
	  else if (value < 1)
	    fail (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "insufficient Stack Safe sanitization");
	  else
	    pass (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, NULL);
	  break;
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case 'o':
      if (streq (attr, "omit_frame_pointer"))
	/* FIXME: Do Something! */
	break;
      /* Fall through.  */

    default:
      einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case GNU_BUILD_ATTRIBUTE_RELRO:
    case GNU_BUILD_ATTRIBUTE_ABI:
    case GNU_BUILD_ATTRIBUTE_STACK_SIZE:
      break;
    }

  return true;
}

static void
ffail (annocheck_data * data, const char * message, int level)
{
  if (! report_future_fail)
    level = VERBOSE2;

  einfo (level, "%s: look: %s", data->filename, message);
  einfo (level, "%s: ^^^^:  This test is not yet enabled, but if it was enabled, it would fail...",
	 data->filename);
}

static void
future_fail (annocheck_data * data, const char * message)
{
  ffail (data, message, INFO);
}

static void
vfuture_fail (annocheck_data * data, const char * message)
{
  ffail (data, message, VERBOSE);
}

static const char *
handle_ppc64_property_note (annocheck_data *      data,
			    annocheck_section *   sec,
			    ulong                 type,
			    ulong                 size,
			    const unsigned char * notedata)
{
  einfo (VERBOSE2, "PPC64 property note handler not yet written...\n");
  return NULL;
}

static const char *
handle_aarch64_property_note (annocheck_data *      data,
			      annocheck_section *   sec,
			      ulong                 type,
			      ulong                 size,
			      const unsigned char * notedata)
{
  /* These are not defined in the RHEL-7 build environment.  */
#ifndef GNU_PROPERTY_AARCH64_FEATURE_1_AND
#define GNU_PROPERTY_AARCH64_FEATURE_1_AND	0xc0000000
#define GNU_PROPERTY_AARCH64_FEATURE_1_BTI	(1U << 0)
#define GNU_PROPERTY_AARCH64_FEATURE_1_PAC	(1U << 1)
#endif
  
  if (type != GNU_PROPERTY_AARCH64_FEATURE_1_AND)
    {
      einfo (VERBOSE2, "%s: Ignoring property note type %lx", data->filename, type);
      return NULL;
    }

  if (size != 4)
    {
      einfo (VERBOSE2, "debug: data note at offset %lx has size %lu, expected 4",
	     (long)(notedata - (const unsigned char *) sec->data->d_buf), size);
      return "Property note data has invalid size";
    }

  ulong property = get_4byte_value (notedata);

  if ((property & GNU_PROPERTY_AARCH64_FEATURE_1_BTI) == 0)
    {
      einfo (VERBOSE2, "debug: property bits = %lx", property);
      vfuture_fail (data, "The BTI property is not enabled");
      return NULL;
    }

  if ((property & GNU_PROPERTY_AARCH64_FEATURE_1_PAC) == 0)
    {
      einfo (VERBOSE2, "debug: property bits = %lx", property);
      vfuture_fail (data, "The PAC property is not enabled");
      return NULL;
    }

  einfo (VERBOSE2, "%s: PASS: Both the BTI and PAC properties are present in the GNU Property note", data->filename);
  return NULL;
}

static const char *
handle_x86_property_note (annocheck_data *      data,
			  annocheck_section *   sec,
			  ulong                 type,
			  ulong                 size,
			  const unsigned char * notedata)
{
  /* These are not defined in the RHEL-7 build environment.  */
#ifndef GNU_PROPERTY_X86_FEATURE_1_AND
#define GNU_PROPERTY_X86_UINT32_AND_LO		0xc0000002
#define GNU_PROPERTY_X86_FEATURE_1_AND          (GNU_PROPERTY_X86_UINT32_AND_LO + 0)
#define GNU_PROPERTY_X86_FEATURE_1_IBT		(1U << 0)
#define GNU_PROPERTY_X86_FEATURE_1_SHSTK	(1U << 1)
#endif

  if (type != GNU_PROPERTY_X86_FEATURE_1_AND)
    {
      einfo (VERBOSE2, "%s: Ignoring property note type %lx", data->filename, type);
      return NULL;
    }

  if (size != 4)
    {
      einfo (VERBOSE2, "debug: data note at offset %lx has size %lu, expected 4",
	     (long)(notedata - (const unsigned char *) sec->data->d_buf), size);
      return "Property note data has invalid size";
    }

  ulong property = get_4byte_value (notedata);

  if ((property & GNU_PROPERTY_X86_FEATURE_1_IBT) == 0)
    {
      einfo (VERBOSE2, "debug: property bits = %lx", property);
      return "The IBT property is not enabled";
    }

  if ((property & GNU_PROPERTY_X86_FEATURE_1_SHSTK) == 0)
    {
      einfo (VERBOSE2, "debug: property bits = %lx", property);
      return "The SHSTK property is not enabled";
    }

  pass (data, TEST_CF_PROTECTION, SOURCE_PROPERTY_NOTES, NULL);
  return NULL;
}

static bool
property_note_checker (annocheck_data *     data,
		       annocheck_section *  sec,
		       GElf_Nhdr *          note,
		       size_t               name_offset,
		       size_t               data_offset,
		       void *               ptr)
{
  const char * reason = NULL;

  if (skip_check (TEST_PROPERTY_NOTE))
    return true;

  const char * (* handler) (annocheck_data *, annocheck_section *, ulong, ulong, const unsigned char *);
  switch (per_file.e_machine)
    {
    case EM_X86_64:
    case EM_386:
      handler = handle_x86_property_note;
      break;

    case EM_AARCH64:
      handler = handle_aarch64_property_note;
      break;

    case EM_PPC64:
      handler = handle_ppc64_property_note;
      break;

    default:
      einfo (VERBOSE2, "%s: WARN: Property notes for architecture %d not handled", data->filename, per_file.e_machine);
      return true;
    }
  
  if (note->n_type != NT_GNU_PROPERTY_TYPE_0)
    {
      einfo (VERBOSE2, "%s: info: unexpected GNU Property note type %x", data->filename, note->n_type);
      return true;
    }

  if (is_executable ())
    {
      /* More than one note in an executable is an error.  */
      if (tests[TEST_PROPERTY_NOTE].state == STATE_PASSED)
	{
	  /* The loader will only process the first note, so having more than one is an error.  */
	  reason = "More than one GNU Property note";
	  goto fail;
	}
    }

  if (note->n_namesz != sizeof ELF_NOTE_GNU
      || strncmp ((char *) sec->data->d_buf + name_offset, ELF_NOTE_GNU, strlen (ELF_NOTE_GNU)) != 0)
    {
      reason = "Property note does not have expected name";
      einfo (VERBOSE2, "debug: Expected name '%s', got '%.*s'", ELF_NOTE_GNU,
	     (int) strlen (ELF_NOTE_GNU), (char *) sec->data->d_buf + name_offset);
      goto fail;
    }

  uint expected_quanta = data->is_32bit ? 4 : 8;
  if (note->n_descsz < 8 || (note->n_descsz % expected_quanta) != 0)
    {
      reason = "Property note data has the wrong size";
      einfo (VERBOSE2, "debug: Expected data size to be a multiple of %d but the size is 0x%x",
	     expected_quanta, note->n_descsz);
      goto fail;
    }

  uint remaining = note->n_descsz;
  const unsigned char * notedata = sec->data->d_buf + data_offset;
  while (remaining)
    {
      ulong type = get_4byte_value (notedata);
      ulong size = get_4byte_value (notedata + 4);

      remaining -= 8;
      notedata  += 8;
      if (size > remaining)
	{
	  reason = "Property note data has invalid size";
	  einfo (VERBOSE2, "debug: data size for note at offset %lx is %lu but remaining data is only %u",
		 (long)(notedata - (const unsigned char *) sec->data->d_buf), size, remaining);
	  goto fail;
	}

      if ((reason = handler (data, sec, type, size, notedata)) != NULL)
	goto fail;

      notedata  += ((size + (expected_quanta - 1)) & ~ (expected_quanta - 1));
      remaining -= ((size + (expected_quanta - 1)) & ~ (expected_quanta - 1));
    }

  pass (data, TEST_PROPERTY_NOTE, SOURCE_PROPERTY_NOTES, NULL);
  return true;

 fail:
  fail (data, TEST_PROPERTY_NOTE, SOURCE_PROPERTY_NOTES, reason);
  return false;
}

static bool
supports_property_notes (int e_machine)
{
  return e_machine == EM_X86_64
    || e_machine == EM_AARCH64
#if 0
    || e_machine == EM_PPC64
#endif
    || e_machine == EM_386;
}

static bool
check_note_section (annocheck_data *    data,
		    annocheck_section * sec)
{
  if (sec->shdr.sh_addralign != 4 && sec->shdr.sh_addralign != 8)
    {
      einfo (INFO, "%s: WARN: note section %s not properly aligned (alignment: %ld)",
	     data->filename, sec->secname, (long) sec->shdr.sh_addralign);
    }

  if (const_strneq (sec->secname, GNU_BUILD_ATTRS_SECTION_NAME))
    {
      bool res;

      per_file.build_notes_seen = true;
      per_file.note_data.start = per_file.note_data.end = 0;
      per_file.seen_tools = TOOL_UNKNOWN;

      res = annocheck_walk_notes (data, sec, build_note_checker, NULL);

      per_file.component_name = NULL;
      if (per_file.note_data.start != per_file.note_data.end)
	add_producer (data, per_file.current_tool, 0, "annobin notes", false);
      return res;
    }

  if (streq (sec->secname, ".note.gnu.property"))
    {
      return annocheck_walk_notes (data, sec, property_note_checker, NULL);
    }

  if (streq (sec->secname, ".note.go.buildid"))
    {
      add_producer (data, TOOL_GO, 0, ".note.go.buildid", true);
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
    fail (data, TEST_THREADS, SOURCE_STRING_SECTION, "not compiled with -fexceptions");

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
  bool dynamic_relocs_seen = false;
  bool aarch64_bti_plt_seen = false;
  bool aarch64_pac_plt_seen = false;

  if (sec->shdr.sh_size == 0 || sec->shdr.sh_entsize == 0)
    {
      einfo (VERBOSE, "%s: WARN: Dynamic section %s is empty - ignoring", data->filename, sec->secname);
      return true;
    }

  if (tests[TEST_DYNAMIC_SEGMENT].state == STATE_UNTESTED)
    pass (data, TEST_DYNAMIC_SEGMENT, SOURCE_DYNAMIC_SECTION, NULL);
  else if (tests[TEST_DYNAMIC_SEGMENT].state == STATE_PASSED)
    fail (data, TEST_DYNAMIC_SEGMENT, SOURCE_DYNAMIC_SECTION, "multiple dynamic sections detected");

  size_t num_entries = sec->shdr.sh_size / sec->shdr.sh_entsize;

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
	  pass (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, NULL);
	  break;

	case DT_FLAGS:
	  if (dyn->d_un.d_val & DF_BIND_NOW)
	    pass (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, NULL);
	  break;

	case DT_RELSZ:
	case DT_RELASZ:
	  if (dyn->d_un.d_val == 0)
	    skip (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "no dynamic relocations");
	  else
	    dynamic_relocs_seen = true;
	  break;

	case DT_TEXTREL:
	  if (is_object_file ())
	    skip (data, TEST_TEXTREL, SOURCE_DYNAMIC_SECTION, "Object files are allowed text relocations");
	  else
	    fail (data, TEST_TEXTREL, SOURCE_DYNAMIC_SECTION, NULL);
	  break;

	case DT_RPATH:
	  {
	    if (skip_check (TEST_RUN_PATH))
	      break;

	    const char * path = elf_strptr (data->elf, sec->shdr.sh_link, dyn->d_un.d_val);

	    if (not_rooted_at_usr (path))
	      fail (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, NULL);
	    else
	      vfuture_fail (data, "The RPATH dynamic tag is deprecated.  Link with --enable-new-dtags to use RUNPATH instead");
	  }
	  break;

	case DT_RUNPATH:
	  {
	    if (skip_check (TEST_RUN_PATH))
	      break;

	    const char * path = elf_strptr (data->elf, sec->shdr.sh_link, dyn->d_un.d_val);

	    if (not_rooted_at_usr (path))
	      fail (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, NULL);
	    else
	      pass (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, NULL);
	  }
	  break;

	case DT_AARCH64_BTI_PLT:
	  aarch64_bti_plt_seen = true;
	  break;

	case DT_AARCH64_PAC_PLT:
	  aarch64_pac_plt_seen = true;
	  break;

	default:
	  break;
	}
    }

  if (dynamic_relocs_seen && tests[TEST_BIND_NOW].state != STATE_PASSED)
    {
      if (! is_executable ())
	skip (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "not an executable");
      else if (per_file.seen_tools & TOOL_GO)
	/* FIXME: Should be changed once GO supports PIE & BIND_NOW.  */
	skip (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "binary was built by GO");
      else
	fail (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "not linked with -Wl,-z,now");
    }

  if (per_file.e_machine == EM_AARCH64)
    {
      if (is_object_file ())
	skip (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "not needed in object files");
      else
	{
	  uint res = aarch64_bti_plt_seen ? 1 : 0;

	  res += aarch64_pac_plt_seen ? 2 : 0;
	  switch (res)
	  {
	  case 0:
	    future_fail (data, "BTI_PLT and PAC_PLT tags missing from dynamic tags");
	    break;
	  case 1:
	    future_fail (data, "PAC_PLT tag is missing from dynamic tags");
	    break;
	  case 2:
	    future_fail (data, "BTI_PLT tag is missing from dynamic tags");
	    break;
	  case 3:
	    pass (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, NULL);
	    break;
	  }
	}
    }

  return true;
}

static bool
check_code_section (annocheck_data *     data,
		    annocheck_section *  sec)
{
  /* At the moment we are only interested in the .comment section.  */
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
      uint version;
      const char * where;

      if ((where = strstr (tool, gcc_prefix)) != NULL)
	{
	  /* FIXME: This assumes that the gcc identifier looks like: "GCC: (GNU) 8.1.1""  */
	  version = (uint) strtod (where + strlen (gcc_prefix), NULL);
	  add_producer (data, TOOL_GCC, version, COMMENT_SECTION, true);
	  einfo (VERBOSE2, "%s: built by gcc version %u (extracted from '%s' in comment section)",
		 data->filename, version, where);
	}
      else if ((where = strstr (tool, clang_prefix)) != NULL)
	{
	  /* FIXME: This assumes that the clang identifier looks like: "clang version 7.0.1""  */
	  version = (uint) strtod (where + strlen (clang_prefix), NULL);
	  add_producer (data, TOOL_CLANG, version, COMMENT_SECTION, true);
	  einfo (VERBOSE2, "%s: built by clang version %u (extracted from '%s' in comment section)",
		 data->filename, version, where);
	}
      else if (strstr (tool, lld_prefix) != NULL)
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
  if (disabled)
    return false;

  /* Note - the types checked here should correspond to the types
     selected in interesting_sec().  */
  switch (sec->shdr.sh_type)
    {
    case SHT_NOTE:     return check_note_section (data, sec);
    case SHT_STRTAB:   return check_string_section (data, sec);
    case SHT_DYNAMIC:  return check_dynamic_section (data, sec);
    case SHT_PROGBITS: return check_code_section (data, sec);
    default:           return true;
    }
}

static bool
is_shared_lib (annocheck_data * data)
{
  /* FIXME: Need a better test.  */
  return strstr (data->filename, ".so") != NULL;
}

static bool
interesting_seg (annocheck_data *    data,
		 annocheck_segment * seg)
{
  if (disabled)
    return false;

  if (! skip_check (TEST_RWX_SEG))
    {
      if ((seg->phdr->p_flags & (PF_X | PF_W | PF_R)) == (PF_X | PF_W | PF_R))
	{
	  /* Object files should not have segments.  */
	  assert (! is_object_file ());
	  fail (data, TEST_RWX_SEG, SOURCE_SEGMENT_HEADERS, "Segment has Read, Write and eXecute flags set");
	  einfo (VERBOSE2, "RWX segment number: %d", seg->number);
	}
    }

  switch (seg->phdr->p_type)
    {
    case PT_GNU_RELRO:
      pass (data, TEST_GNU_RELRO, SOURCE_SEGMENT_HEADERS, NULL);
      break;

    case PT_GNU_STACK:
      if (! skip_check (TEST_GNU_STACK))
	{
	  if ((seg->phdr->p_flags & (PF_W | PF_R)) != (PF_W | PF_R))
	    fail (data, TEST_GNU_STACK, SOURCE_SEGMENT_HEADERS, "The GNU stack segment does not have both read & write permissions");
	  /* If the segment has the PF_X flag set it will have been reported as a failure above.  */
	  else if ((seg->phdr->p_flags & PF_X) == 0)
	    pass (data, TEST_GNU_STACK, SOURCE_SEGMENT_HEADERS, NULL);
	}
      break;

    case PT_DYNAMIC:
      pass (data, TEST_DYNAMIC_SEGMENT, SOURCE_SEGMENT_HEADERS, NULL);
      /* FIXME: We do not check to see if there is a second dynamic segment.
	 Checking is complicated by the fact that there can be both a dynamic
	 segment and a dynamic section.  */
      break;

    case PT_NOTE:
      if (skip_check (TEST_PROPERTY_NOTE))
	break;
      /* We return true if we want to examine the note segments.  */
      return supports_property_notes (per_file.e_machine);

    case PT_LOAD:
      /* If we are checking the entry point instruction then we need to load
	 the segment.  We check segments rather than sections because executables
	 do not have to have sections.  */
      if (per_file.e_type == ET_DYN
	  && is_x86 ()
	  && ! is_shared_lib (data)
	  && seg->phdr->p_memsz > 0
	  && seg->phdr->p_vaddr <= per_file.e_entry
	  && seg->phdr->p_vaddr + seg->phdr->p_memsz > per_file.e_entry
	  && ! skip_check (TEST_ENTRY))
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
  if (disabled)
    return false;

  if (seg->phdr->p_type == PT_LOAD)
    {
      Elf64_Addr entry_point = per_file.e_entry - seg->phdr->p_vaddr;

      /* We are checking the entry point instruction.  We should
	 only have reached this point if the requirements for the
	 check have already been met, so we do not need to test
	 them again.  */
      assert (entry_point + 3 < seg->data->d_size);
      memcpy (entry_bytes, seg->data->d_buf + entry_point, sizeof entry_bytes);

      if (tests[TEST_ENTRY].state == STATE_MAYBE)
	; /* A signal from interesting_seg() that this is interpreted code.  */
      else if (per_file.e_machine == EM_386)
	{
	  /* Look for ENDBR32: 0xf3 0x0f 0x1e 0xfb. */
	  if (   entry_bytes[0] == 0xf3
	      && entry_bytes[1] == 0x0f
	      && entry_bytes[2] == 0x1e
	      && entry_bytes[3] == 0xfb)
	    pass (data, TEST_ENTRY, SOURCE_SEGMENT_CONTENTS, NULL);
	  else
	    {
	      fail (data, TEST_ENTRY, SOURCE_SEGMENT_CONTENTS, "instruction at entry is not ENDBR32");

	      einfo (VERBOSE, "%s: info: entry address: %#lx.  Bytes at this address: %x %x %x %x",
		     data->filename, (long) per_file.e_entry,
		     entry_bytes[0], entry_bytes[1], entry_bytes[2], entry_bytes[3]);
	    }
	}
      else /* per_file.e_machine == EM_X86_64 */
	{
	  /* Look for ENDBR64: 0xf3 0x0f 0x1e 0xfa.  */
	  if (   entry_bytes[0] == 0xf3
	      && entry_bytes[1] == 0x0f
	      && entry_bytes[2] == 0x1e
	      && entry_bytes[3] == 0xfa)
	    pass (data, TEST_ENTRY, SOURCE_SEGMENT_CONTENTS, NULL);
	  else
	    {
	      fail (data, TEST_ENTRY, SOURCE_SEGMENT_CONTENTS, "instruction at entry is not ENDBR64");

	      einfo (VERBOSE, "%s: info: entry address: %#lx.  Bytes at this address: %x %x %x %x",
		     data->filename, (long) per_file.e_entry,
		     entry_bytes[0], entry_bytes[1], entry_bytes[2], entry_bytes[3]);
	    }
	}

      return true;
    }

  if (seg->phdr->p_type != PT_NOTE)
    return true;
    
  if (per_file.e_machine != EM_X86_64)
    return true;

  if (skip_check (TEST_PROPERTY_NOTE))
    return true;

  /* FIXME: Only run these checks if the note section is missing ?  */

  GElf_Nhdr  note;
  size_t     name_off;
  size_t     data_off;
  size_t     offset = 0;

  offset = gelf_getnote (seg->data, offset, & note, & name_off, & data_off);

  if (seg->phdr->p_align != 8)
    {
      if (seg->phdr->p_align != 4)
	{
	  fail (data, TEST_PROPERTY_NOTE, SOURCE_SEGMENT_CONTENTS, "Note segment not 4 or 8 byte aligned");
	  einfo (VERBOSE2, "debug: note segment alignment: %ld", (long) seg->phdr->p_align);
	}
      else if (note.n_type == NT_GNU_PROPERTY_TYPE_0)
	{
	  fail (data, TEST_PROPERTY_NOTE, SOURCE_SEGMENT_CONTENTS, "GNU Property note segment not 8 byte aligned");
	}
    }

  if (note.n_type == NT_GNU_PROPERTY_TYPE_0)
    {
      if (offset != 0)
	fail (data, TEST_PROPERTY_NOTE, SOURCE_SEGMENT_CONTENTS, "More than one GNU Property note in note segment");
      else
	/* FIXME: We should check the contents of the note.  */
	pass (data, TEST_PROPERTY_NOTE, SOURCE_SEGMENT_CONTENTS, NULL);
    }

  return true;
}

/* Returns true if GAP is one that can be ignored.  */

static bool
ignore_gap (annocheck_data * data, note_range * gap)
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
  note_range * n1 = (note_range *) r1;
  note_range * n2 = (note_range *) r2;

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
  if (sym == NULL)
    return false;

  /* G++ will generate virtual and non-virtual thunk functions all on its own,
     without telling the annobin plugin about them.  Detect them here and do
     not complain about the gap in the coverage.  */
  if (const_strneq (sym, "_ZThn") || const_strneq (sym, "_ZTv0"))
    return true;

  /* The GO infrastructure is not annotated.  */
  if (const_strneq (sym, "internal/cpu.Initialize"))
    return true;

  /* If the symbol is for a function/file that we know has special
     reasons for not being proplerly annotated then we skip it.  */
  const char * saved_sym = per_file.component_name;
  per_file.component_name = sym;
  if (skip_check (TEST_MAX))
    {
      per_file.component_name = saved_sym;
      return true;
    }
  per_file.component_name = saved_sym;

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

  note_range current = ranges[0];

  /* Scan the ranges array.  */
  bool gap_found = false;
  uint i;
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
	  note_range gap;

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

	      einfo (VERBOSE, "%s: gap:  (%#lx..%#lx probable component: %s) in annobin notes",
		     data->filename, gap.start, gap.end, sym);

	      free ((char *) cpsym);
	    }
	  else
	    einfo (VERBOSE, "%s: gap:  (%#lx..%#lx) in annobin notes",
		   data->filename, gap.start, gap.end);
	}
    }

  if (! gap_found)
    pass (data, TEST_NOTES, SOURCE_ANNOBIN_NOTES, "no gaps found");
  else
    fail (data, TEST_NOTES, SOURCE_ANNOBIN_NOTES, "gaps were detected in the annobin coverage");

  /* Now check to see that the notes covered the whole of the .text section.  */
  /* FIXME: We should actually do this for an executable section.  */
  
  /* Scan forward through the ranges array looking for overlaps with the start of the .text section.  */
  if (per_file.text_section_range.end != 0)
    {
      for (i = 0; i < next_free_range; i++)
	{
	  if (ranges[i].start <= per_file.text_section_range.start
	      && ranges [i].end > per_file.text_section_range.start)
	    /* We have found a note range the occludes the start of the text section.
	       Move the start up to the end of this note, aligned to 16 bytes.  */
	    {
	      per_file.text_section_range.start = align (ranges[i].end, 16);
	      if (per_file.text_section_range.start >= per_file.text_section_range.end)
		{
		  per_file.text_section_range.start = per_file.text_section_range.end = 0;
		  break;
		}
	    }
	}
    }

  /* Now scan backwards through the ranges array looking for overlaps with the end of the .text section.  */
  if (per_file.text_section_range.end != 0)
    {
      for (i = next_free_range; i--;)
	{
	  if (ranges[i].start < per_file.text_section_range.end
	      && align (ranges [i].end, 16) >= per_file.text_section_range.end)
	    /* We have found a note range the occludes the end of the text section.
	       Move the end up to the start of this note, aligned to 16 bytes.  */
	    {
	      per_file.text_section_range.end = align (ranges[i].start - 15, 16);
	      if (per_file.text_section_range.start >= per_file.text_section_range.end)
		{
		  per_file.text_section_range.start = per_file.text_section_range.end = 0;
		  break;
		}
	    }
	}
    }

  if (per_file.text_section_range.end > 0)
    {
      /* This test does not account for ranges that occlude part
	 of the .text section, so make it an INFO result for now.
	 Nor does it allow for linker generated code that have no notes.  */
      einfo (VERBOSE, "%s: info: not all of the .text section is covered by notes",
	     data->filename);
      einfo (VERBOSE, "%s: info: addr range not covered: %lx..%lx",
	     data->filename, per_file.text_section_range.start, per_file.text_section_range.end);
    }
}


static bool
finish (annocheck_data * data)
{
  if (disabled || per_file.debuginfo_file)
    return true;

  if (! per_file.build_notes_seen
      /* NB/ This code must happen after the call to annocheck_walk_dwarf()
	 as that function is responsible for following links to debuginfo
	 files.  */
      && data->dwarf_filename != NULL
      && data->dwarf_fd != data->fd)
    {
      struct checker hardened_notechecker =
	{
	 HARDENED_CHECKER_NAME,
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
      einfo (VERBOSE2, "%s: info: running subchecker on %s", data->filename, data->dwarf_filename);
      annocheck_process_extra_file (& hardened_notechecker, data->dwarf_filename, data->filename, data->dwarf_fd);
    }

  if (! per_file.build_notes_seen && is_C_compiler (per_file.seen_tools))
    fail (data, TEST_NOTES, SOURCE_ANNOBIN_NOTES, "Annobin notes were not found");

  if (! ignore_gaps)
    {
      if (is_object_file ())
	einfo (VERBOSE, "%s: Not checking for gaps (object file)", data->filename);
      else if (! is_C_compiler (per_file.seen_tools) && ! includes_assembler (per_file.seen_tools))
	einfo (VERBOSE, "%s: Not checking for gaps (binary created by a tool without an annobin plugin)",
	       data->filename);
      else
	check_for_gaps (data);
    }

  if (per_file.seen_tools == TOOL_UNKNOWN)
    per_file.seen_tools = per_file.current_tool;

  int i;
  for (i = 0; i < TEST_MAX; i++)
    {
      if (! tests[i].enabled)
	continue;

      if (tests[i].state == STATE_UNTESTED)
	{
	  switch (i)
	    {
	    case TEST_GNU_STACK:
	    case TEST_NOTES:
	    case TEST_LTO:
	    case TEST_ENTRY:
	    case TEST_SHORT_ENUM:
	    case TEST_DYNAMIC_SEGMENT:
	    case TEST_RUN_PATH:
	    case TEST_RWX_SEG:
	    case TEST_TEXTREL:
	    case TEST_THREADS:
	    case TEST_WRITEABLE_GOT:
	      /* The absence of a result for these tests actually means that they have passed.  */
	      pass (data, i, SOURCE_FINAL_SCAN, NULL);
	      break;

	    case TEST_BIND_NOW:
	      if (! is_executable ())
		skip (data, i, SOURCE_FINAL_SCAN, "only needed for executables");
	      else if (tests[TEST_DYNAMIC_SEGMENT].state == STATE_UNTESTED)
		skip (data, i, SOURCE_FINAL_SCAN, "no dynamic segment present");
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "no dynamic relocs found");
	      break;

	    case TEST_GNU_RELRO:
	      if (is_object_file ())
		skip (data, i, SOURCE_FINAL_SCAN, "not needed in object files");
	      else if (tests[TEST_DYNAMIC_SEGMENT].state == STATE_UNTESTED)
		skip (data, i, SOURCE_FINAL_SCAN, "no dynamic segment present");
	      else if (tests [TEST_BIND_NOW].state == STATE_UNTESTED)
		skip (data, i, SOURCE_FINAL_SCAN, "no dynamic relocations");
	      else if (per_file.seen_tools & TOOL_GO)
		/* FIXME: This is for GO binaries.  Should be changed once GO supports PIE & BIND_NOW.  */
		skip (data, i, SOURCE_FINAL_SCAN, "built by GO");
	      else
		fail (data, i, SOURCE_FINAL_SCAN, "not linked with -Wl,-z,relro");
	      break;

	    case TEST_DYNAMIC_TAGS:
	      if (per_file.e_machine != EM_AARCH64)
		skip (data, i, SOURCE_FINAL_SCAN, "AArch64 specific");
	      else if (is_object_file ())
		skip (data, i, SOURCE_FINAL_SCAN, "not needed in object files");
	      else
		future_fail (data, "no dynamic tags found");
	      break;

	    case TEST_GLIBCXX_ASSERTIONS:
	      if (per_file.lang != LANG_UNKNOWN && per_file.lang != LANG_CXX)
		{
		  skip (data, i, SOURCE_FINAL_SCAN, "source language not C++");
		  break;
		}
	      /* Fall through.  */
	    case TEST_WARNINGS:
	    case TEST_FORTIFY:
	      if (tests[TEST_LTO].state == STATE_PASSED)
		{
		  skip (data, i, SOURCE_FINAL_SCAN, "compiling in LTO mode hides preprocessor and warning options");
		  break;
		}
	      else if (is_C_compiler (per_file.seen_tools))
		{
		  fail (data, i, SOURCE_FINAL_SCAN, "no indication that the necessary option was used");
		  break;
		}
	      else if (per_file.current_tool == TOOL_GO)
		{
		  skip (data, i, SOURCE_FINAL_SCAN, "GO compilation does not use the C preprocessor");
		  break;
		}
	      /* Fall through.  */
	    default:
	      /* Do not complain about compiler specific tests being missing
		 if all that we have seen is assembler produced code.  */
	      if (per_file.seen_tools == TOOL_GAS
		  || (per_file.gcc_from_comment && per_file.seen_tools == (TOOL_GAS | TOOL_GCC)))
		skip (data, i, SOURCE_FINAL_SCAN, "no compiled code found");
	      /* There may be notes on this test, but the are for a zero-length range.  */
	      else
		maybe (data, i, SOURCE_FINAL_SCAN, "no valid notes found regarding this test");
	      break;

	    case TEST_PIC:
	      if (per_file.current_tool == TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "GO does not support a -fPIC option");
	      else if (is_C_compiler (per_file.seen_tools))
		maybe (data, i, SOURCE_FINAL_SCAN, "no valid notes found regarding this test");
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "not compiled code");
	      break;

	    case TEST_STACK_PROT:
	      if (per_file.current_tool == TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "GO is stack safe");
	      else if (is_C_compiler (per_file.seen_tools))
		maybe (data, i, SOURCE_FINAL_SCAN, "no valid notes found regarding this test");
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "not compiled code");
	      break;

	    case TEST_OPTIMIZATION:
	      if (per_file.current_tool == TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "GO optimizes by default");
	      else if (is_C_compiler (per_file.seen_tools))
		maybe (data, i, SOURCE_FINAL_SCAN, "no valid notes found regarding this test");
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "not compiled code");
	      break;

	    case TEST_STACK_CLASH:
	      if (per_file.e_machine == EM_ARM)
		skip (data, i, SOURCE_FINAL_SCAN, "not support on ARM architectures");
	      else if (per_file.seen_tools == TOOL_GAS
		       || (per_file.gcc_from_comment && per_file.seen_tools == (TOOL_GAS | TOOL_GCC)))
		skip (data, i, SOURCE_FINAL_SCAN, "no compiled code found");
	      else if (per_file.current_tool == TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "GO is stack safe");
	      else if (is_C_compiler (per_file.seen_tools))
		skip (data, i, SOURCE_FINAL_SCAN, "no compiled code found");
	      else
		maybe (data, i, SOURCE_FINAL_SCAN, "no notes found regarding this test");
	    break;

	    case TEST_PROPERTY_NOTE:
	      if (! supports_property_notes (per_file.e_machine))
		skip (data, i, SOURCE_FINAL_SCAN, "property notes not used");
	      else if (is_object_file ())
		skip (data, i, SOURCE_FINAL_SCAN, "property notes not needed in object files");
	      else if (per_file.current_tool == TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "property notes not needed for GO binaries");
	      else if (per_file.e_machine == EM_AARCH64)
		future_fail (data, ".note.gnu.property section not found");
	      else
		fail (data, i, SOURCE_FINAL_SCAN, "no .note.gnu.property section found");
	      break;

	    case TEST_CF_PROTECTION:
	      if (is_x86 () && is_executable ())
		{
		  if (per_file.current_tool == TOOL_GO)
		    skip (data, i, SOURCE_FINAL_SCAN, "control flow protection is not needed for GO binaries");
		  else if (tests[TEST_PROPERTY_NOTE].enabled
		      && tests[TEST_PROPERTY_NOTE].state == STATE_UNTESTED)
		    fail (data, i, SOURCE_FINAL_SCAN, "no .note.gnu.property section = no control flow information");
		  else
		    fail (data, i, SOURCE_FINAL_SCAN, "control flow protection is not enabled");
		}
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "not an x86 executable");
	      break;

	    case TEST_STACK_REALIGN:
	      if (per_file.seen_tools == TOOL_GAS
		  || (per_file.gcc_from_comment && per_file.seen_tools == (TOOL_GAS | TOOL_GCC)))
		skip (data, i, SOURCE_FINAL_SCAN, "no compiled code found");
	      else if (per_file.e_machine == EM_386)
		fail  (data, i, SOURCE_FINAL_SCAN, "stack realign support is mandatory");
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "not an x86 executable");
	      break;

	    case TEST_BRANCH_PROTECTION:
	      if (per_file.e_machine != EM_AARCH64)
		skip (data, i, SOURCE_FINAL_SCAN, "not an AArch64 binary");
	      else if (! includes_gcc (per_file.seen_tools) && ! includes_gimple (per_file.current_tool))
		skip (data, i, SOURCE_FINAL_SCAN, "not built by gcc");
	      else if (per_file.tool_version < 9)
		skip (data, i, SOURCE_FINAL_SCAN, "needs gcc 9+");
	      else
		/* FIXME: Only inform the user for now.  Once -mbranch-protection has
		   been added to the rpm macros then change this result to a maybe().  */
		/* maybe (data, "The -mbranch-protection setting was not recorded");  */
		future_fail (data, "The -mbranch-protection setting was not recorded");
	      break;

	    case TEST_GO_REVISION:
	      if (per_file.seen_tools & TOOL_GO)
		fail (data, i, SOURCE_FINAL_SCAN, "no Go compiler revision information found");
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "no GO compiled code found");

	    case TEST_ONLY_GO:
	      if (! is_x86 ())
		skip (data, i, SOURCE_FINAL_SCAN, "not compiled for x86");
	      else if (per_file.seen_tools == TOOL_GO)
		pass (data, i, SOURCE_FINAL_SCAN, "only GO compiled code found");
	      else if (per_file.seen_tools & TOOL_GO)
		fail (data, i, SOURCE_FINAL_SCAN, "mixed GO and another language found");
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "no GO compiled code found");
	      break;
	    }
	}
    }

  if (per_file.num_fails > 0)
    {
      static bool tell_rerun = true;
      if (! BE_VERBOSE && tell_rerun)
	{
	  einfo (INFO, "Rerun annocheck with --verbose to see more information on the tests");
	  tell_rerun = false;
	}
      return false;
    }

  if (per_file.num_maybes > 0)
    return false; /* FIXME: Add an option to ignore MAYBE results ? */

  if (BE_VERBOSE)
    return true;

  return einfo (INFO, "%s: PASS", data->filename);
}

static void
version (void)
{
  einfo (INFO, "Version 1.4");
}

static void
usage (void)
{
  einfo (INFO, "Hardening/Security checker.  By default all relevant tests are run.");
  einfo (INFO, "  To disable an individual test use the following options:");

  int i;
  for (i = 0; i < TEST_MAX; i++)
    einfo (INFO, "    --skip-%-19sDisables: %s", tests[i].name, tests[i].description);

  einfo (INFO, "    --skip-%-19sDisables all tests", "all");
  einfo (INFO, "  To enable a disabled test use --test-<name>");
  
  einfo (INFO, "  The tool will also report missing annobin data unless:");
  einfo (INFO, "    --ignore-gaps             Ignore missing annobin data");

  einfo (INFO, "  The tool is enabled by default.  This can be changed by:");
  einfo (INFO, "    --disable-hardened        Disables the hardening checker");
  einfo (INFO, "    --enable-hardened         Reenables the hardening checker");

  einfo (INFO, "   The tool will generate messages based upon the verbosity level");
  einfo (INFO, "   but the format is not fixed.  In order to have a consistent");
  einfo (INFO, "   output enable this option:");
  einfo (INFO, "     --fixed-format-messages");
}

static bool
process_arg (const char * arg, const char ** argv, const uint argc, uint * next)
{
  if (const_strneq (arg, "--skip-"))
    {
      arg += strlen ("--skip-");

      int i;

      if (streq (arg, "all"))
	{
	  for (i = 0; i < TEST_MAX; i++)
	    tests[i].enabled = false;
	  return true;
	}
      
      if (streq (arg, "future"))
	{
	  report_future_fail = false;
	  return true;
	}
      
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

  if (const_strneq (arg, "--test-"))
    {
      arg += strlen ("--test-");

      int i;

      if (streq (arg, "all"))
	{
	  for (i = 0; i < TEST_MAX; i++)
	    tests[i].enabled = true;
	  return true;
	}
      
      if (streq (arg, "future"))
	{
	  report_future_fail = true;
	  return true;
	}
      
      for (i = 0; i < TEST_MAX; i++)
	{
	  if (streq (arg, tests[i].name))
	    {
	      tests[i].enabled = true;
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

  if (streq (arg, "--fixed-format-messages"))
    {
      fixed_format_messages = true;
      return true;
    }

  return false;
}


struct checker hardened_checker =
{
  HARDENED_CHECKER_NAME,
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
