/* Checks the hardened status of the given file.
   Copyright (c) 2018 - 2022 Red Hat.

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
#define EM_AARCH64	183	/* ARM 64-bit architecture.  */
#endif

#define HARDENED_CHECKER_NAME   "Hardened"

/* Predefined names for all of the sources of information scanned by this checker.  */
#define SOURCE_ANNOBIN_NOTES    "annobin notes"
#define SOURCE_COMMENT_SECTION  "comment section"
#define SOURCE_DW_AT_LANGUAGE   "DW_AT_language string"
#define SOURCE_DW_AT_PRODUCER   "DW_AT_producer string"
#define SOURCE_DYNAMIC_SECTION  "dynamic section"
#define SOURCE_DYNAMIC_SEGMENT  "dynamic segment"
#define SOURCE_ELF_HEADER       "ELF header"
#define SOURCE_FINAL_SCAN       "final scan"
#define SOURCE_PROPERTY_NOTES   "property notes"
#define SOURCE_RODATA_SECTION   ".rodata section"
#define SOURCE_SECTION_HEADERS  "section headers"
#define SOURCE_SEGMENT_CONTENTS "segment contents"
#define SOURCE_SEGMENT_HEADERS  "segment headers"
#define SOURCE_SKIP_CHECKS      "special case exceptions"
#define SOURCE_STRING_SECTION   "string section"
#define SOURCE_SYMBOL_SECTION   "symbol section"

#define GOLD_COLOUR     "\e[33;40m"
#define RED_COLOUR      "\x1B[31;47m"
#define DEFAULT_COLOUR  "\033[0m"

typedef struct note_range
{
  ulong         start;
  ulong         end;
} note_range;

/* Set by the constructor.  */
static bool disabled = false;

/* Can be changed by command line options.  */
static bool ignore_gaps = false;
static bool fixed_format_messages = false;
static bool enable_colour = true;

typedef struct bool_option
{
  bool option_set;
  bool option_value;
} bool_option;

static bool_option         full_filename = { false, false };
#define USE_FULL_FILENAME  (full_filename.option_value == true)

static bool_option         provide_url = { false, true };
#define PROVIDE_A_URL      (provide_url.option_value == true)

static bool_option         dt_rpath_is_ok = { false, true };
#define DT_RPATH_OK        (dt_rpath_is_ok.option_value == true)

static bool_option 	   fail_for_all_unicode = { false, false };
#define FAIL_FOR_ANY_UNICODE  (fail_for_all_unicode.option_value == true)

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
   The fields are initialised by start(), which by default sets them to 0/false.  */
static struct per_file
{
  Elf64_Half  e_type;
  Elf64_Half  e_machine;
  Elf64_Addr  e_entry;

  ulong       text_section_name_index;
  ulong       text_section_alignment;
  note_range  text_section_range;

  int         num_fails;
  int         num_maybes;
  uint        anno_major;
  uint        anno_minor;
  uint        anno_rel;
  uint        run_major;
  uint        run_minor;
  uint        run_rel;
  uint        annobin_gcc_date;
  uint        gcc_date;
  
  uint          seen_tools_with_code;
  uint          seen_tools;
  uint          tool_version;
  uint          current_tool;
  note_range    note_data;

  const char *  component_name;
  uint          component_type;

  enum short_enum_state short_enum_state;

  uint        note_source[256];

  enum lang   lang;

  bool        is_little_endian;
  bool        debuginfo_file;
  bool        build_notes_seen;
  bool        gcc_from_comment;
  bool        warned_asm_not_gcc;
  bool        warned_about_instrumentation;
  bool        warned_version_mismatch;
  bool        warned_command_line;
  bool        other_language;
  bool        also_written;
  bool	      has_pie_flag;
  bool	      has_soname;
  bool	      has_program_interpreter;
  bool	      has_dt_debug;
  bool        has_cf_protection;
  bool        has_property_note;
  bool        has_modinfo;
  bool        has_gnu_linkonce_this_module;
  bool        has_dynamic_segment;
  bool        has_module_license;
  bool        has_modname;
  bool        lto_used;
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
  const char *      doc_url;      /* Online description of the test.  */
} test;

enum test_index
{
  TEST_NOTES = 0,

  TEST_BIND_NOW,
  TEST_BRANCH_PROTECTION,
  TEST_NOT_BRANCH_PROTECTION,
  TEST_CF_PROTECTION,
  TEST_DYNAMIC_SEGMENT,
  TEST_DYNAMIC_TAGS,
  TEST_NOT_DYNAMIC_TAGS,
  TEST_ENTRY,
  TEST_FORTIFY,
  TEST_GLIBCXX_ASSERTIONS,
  TEST_GNU_RELRO,
  TEST_GNU_STACK,
  TEST_GO_REVISION,
  TEST_INSTRUMENTATION,
  TEST_LTO,
  TEST_ONLY_GO,
  TEST_OPTIMIZATION,
  TEST_PIC,
  TEST_PIE,
  TEST_PRODUCTION,
  TEST_PROPERTY_NOTE,
  TEST_RUN_PATH,
  TEST_RWX_SEG,
  TEST_SHORT_ENUMS,
  TEST_STACK_CLASH,
  TEST_STACK_PROT,
  TEST_STACK_REALIGN,
  TEST_TEXTREL,
  TEST_THREADS,
  TEST_UNICODE,
  TEST_WARNINGS,
  TEST_WRITABLE_GOT,

  TEST_MAX
};

enum profile
{
  PROFILE_NONE = 0,
  PROFILE_EL7,
  PROFILE_EL8,
  PROFILE_EL9,
  PROFILE_RAWHIDE,

  PROFILE_MAX
};

static enum profile current_profile = PROFILE_NONE;

#define MIN_GO_REVISION 14
#define STR(a) #a
#define MIN_GO_REV_STR(a,b,c) a STR(b) c

#define TEST(name,upper,description)						\
  [ TEST_##upper ] = { true, false, false, STATE_UNTESTED, #name, description,	\
    "https://sourceware.org/annobin/annobin.html/Test-" #name ".html" }

/* Array of tests to run.  Default to enabling them all.
   The result field is initialised in the start() function.  */
static test tests [TEST_MAX] =
{
  TEST (notes,              NOTES,              "Annobin note coverage (not ARM)"),
  TEST (bind-now,           BIND_NOW,           "Linked with -Wl,-z,now"),
  TEST (branch-protection,  BRANCH_PROTECTION,  "Compiled with -mbranch-protection=bti (AArch64 only, gcc 9+ only, Fedora"),
  TEST (not-branch-protection,  NOT_BRANCH_PROTECTION,  "Compiled without -mbranch-protection=bti (AArch64 only, gcc 9+ only, RHEL-9"),
  TEST (cf-protection,      CF_PROTECTION,      "Compiled with -fcf-protection=all (x86 only, gcc 8+ only)"),
  TEST (dynamic-segment,    DYNAMIC_SEGMENT,    "There is at most one dynamic segment/section"),
  TEST (dynamic-tags,       DYNAMIC_TAGS,       "Dynamic tags for BTI (and optionally PAC) present (AArch64 only, Fedora)"),
  TEST (not-dynamic-tags,   NOT_DYNAMIC_TAGS,   "Dynamic tags for PAC & BTI *not* present (AArch64 only, RHEL-9)"),
  TEST (entry,              ENTRY,              "The first instruction is ENDBR (x86 executables only)"),
  TEST (fortify,            FORTIFY,            "Compiled with -D_FORTIFY_SOURCE=2"),
  TEST (glibcxx-assertions, GLIBCXX_ASSERTIONS, "Compiled with -D_GLIBCXX_ASSERTIONS"),
  TEST (gnu-relro,          GNU_RELRO,          "The relocations for the GOT are not writable"),
  TEST (gnu-stack,          GNU_STACK,          "The stack is not executable"),
  TEST (go-revision,        GO_REVISION,        MIN_GO_REV_STR ("GO compiler revision >= ", MIN_GO_REVISION, " (go only)")),
  TEST (instrumentation,    INSTRUMENTATION,    "Compiled without code instrumentation"),
  TEST (lto,                LTO,                "Compiled with -flto"),
  TEST (only-go,            ONLY_GO,            "GO is not mixed with other languages.  (go only, x86 only)"),
  TEST (optimization,       OPTIMIZATION,       "Compiled with at least -O2"),
  TEST (pic,                PIC,                "All binaries must be compiled with -fPIC or -fPIE"),
  TEST (pie,                PIE,                "Executables need to be compiled with -fPIE"),
  TEST (production,         PRODUCTION,         "Built by a production compiler, not an experimental one"),
  TEST (property-note,      PROPERTY_NOTE,      "Correctly formatted GNU Property notes"),
  TEST (run-path,           RUN_PATH,           "All runpath entries are secure"),
  TEST (rwx-seg,            RWX_SEG,            "There are no segments that are both writable and executable"),
  TEST (short-enums,        SHORT_ENUMS,        "Compiled with consistent use of -fshort-enums"),
  TEST (stack-clash,        STACK_CLASH,        "Compiled with -fstack-clash-protection (not ARM)"),
  TEST (stack-prot,         STACK_PROT,         "Compiled with -fstack-protector-strong"),
  TEST (stack-realign,      STACK_REALIGN,      "Compiled with -mstackrealign (i686 only)"),
  TEST (textrel,            TEXTREL,            "There are no text relocations in the binary"),
  TEST (threads,            THREADS,            "Compiled with -fexceptions"),
  TEST (unicode,            UNICODE,            "No unicode symbol names"),
  TEST (warnings,           WARNINGS,           "Compiled with -Wall"),
  TEST (writable-got,       WRITABLE_GOT,       "The .got section is not writable"),
};

/* Default to not reporting future fails - it could confuse ordinary users.  */
static bool report_future_fail = false;

static inline bool
startswith (const char *str, const char *prefix)
{
  return strncmp (str, prefix, strlen (prefix)) == 0;
}

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

static inline const char *
get_filename (annocheck_data * data)
{
  if (USE_FULL_FILENAME)
    return data->full_filename;
  else
    return data->filename;
}

static inline void
go_red (void)
{
  if (enable_colour && isatty (1))
    einfo (PARTIAL, RED_COLOUR);
}

static inline void
go_default_colour (void)
{
  if (enable_colour && isatty (1))
    einfo (PARTIAL, DEFAULT_COLOUR);
}

static inline void
go_gold (void)
{
  if (enable_colour && isatty (1))
    einfo (PARTIAL, GOLD_COLOUR);
}

static void
warn (annocheck_data * data, const char * message)
{
  if (fixed_format_messages)
    return;

  einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, get_filename (data));

  go_red ();

  einfo (PARTIAL, "WARN: %s", message);

  go_default_colour ();

  einfo (PARTIAL, "\n");
}

static void
inform (annocheck_data * data, const char * message)
{
  if (fixed_format_messages)
    return;
  einfo (VERBOSE, "%s: %s", get_filename (data), message);
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

  const char * filename = get_filename (data);

  if (fixed_format_messages)
    {
      const char * fname = sanitize_filename (filename);
      einfo (INFO, FIXED_FORMAT_STRING, "PASS", tests[testnum].name, fname);
      if (fname != filename)
	free ((void *) fname);
    }
  else
    {
      if (! BE_VERBOSE)
	return;

      einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, filename);
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

  einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, get_filename (data));
  einfo (PARTIAL, "skip: %s test ", tests[testnum].name);
  if (reason)
    einfo (PARTIAL, "because %s ", reason);
  if (BE_VERY_VERBOSE)
    einfo (PARTIAL, " (source: %s)\n", source);
  else
    einfo (PARTIAL, "\n");
}

static inline void
show_url (uint testnum, const char * filename)
{
  if (PROVIDE_A_URL)
    einfo (PARTIAL,  "%s: %s: info: For more information visit: %s\n",
	   HARDENED_CHECKER_NAME, filename, tests[testnum].doc_url);
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

  const char * filename = get_filename (data);

  if (fixed_format_messages)
    {
      const char * fname = sanitize_filename (filename);
      einfo (INFO, FIXED_FORMAT_STRING, "FAIL", tests[testnum].name, fname);
      if (fname != filename)
	free ((void *) fname);
    }
  else if (tests[testnum].state != STATE_FAILED || BE_VERBOSE)
    {
      einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, filename);
      go_red ();
      einfo (PARTIAL, "FAIL: %s test ", tests[testnum].name);
      if (reason)
	einfo (PARTIAL, "because %s ", reason);

      const char * name = per_file.component_name;
      if (name && BE_VERBOSE)
	{
	  if (startswith (name, "component: "))
	    einfo (PARTIAL, "(function: %s) ", name + strlen ("component: "));
	  else
	    einfo (PARTIAL, "(%s) ", name);
	}

      go_default_colour ();

      if (BE_VERY_VERBOSE)
	einfo (PARTIAL, "(source: %s)", source);

      einfo (PARTIAL, "\n");

      show_url (testnum, filename);
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

  const char * filename = get_filename (data);

  if (fixed_format_messages)
    {
      const char * fname = sanitize_filename (filename);
      einfo (INFO, FIXED_FORMAT_STRING, "MAYB", tests[testnum].name, fname);
      if (fname != filename)
	free ((void *) fname);
    }
  else if (tests[testnum].state == STATE_UNTESTED || BE_VERBOSE)
    {
      einfo (PARTIAL, "%s: %s: ", HARDENED_CHECKER_NAME, filename);

      go_gold ();

      einfo (PARTIAL, "MAYB: test: %s ", tests[testnum].name);
      if (reason)
	einfo (PARTIAL, "because %s ", reason);
      if (per_file.component_name)
	{
	  const char * name = per_file.component_name;

	  if (startswith (name, "component: "))
	    einfo (PARTIAL, "(function: %s) ", name + strlen ("component: "));
	  else
	    einfo (PARTIAL, "(%s) ", name);
	}
      go_default_colour ();

      if (BE_VERY_VERBOSE)
	einfo (PARTIAL, " (source: %s)", source);

      einfo (PARTIAL, "\n");

      show_url (testnum, filename);
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

  einfo (VERBOSE2, "%s: info: %s %s (source %s)", get_filename (data),
	 tests[testnum].name, extra, source);
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
	     get_filename (data), get_lang_name (lang), source);

      per_file.lang = lang;
    }
  else if (per_file.lang == lang)
    ;
  else
    {
      if (! per_file.also_written)
	{
	  einfo (VERBOSE, "%s: info: ALSO written in %s (source: %s)",
		 get_filename (data), get_lang_name (lang), source);
	  per_file.also_written = true;
	}

      if (is_x86 () && (lang == LANG_GO || per_file.lang == LANG_GO))
	{
	  /* FIXME: This FAIL is only true if CET is not enabled.  */
	  if (tests[TEST_ONLY_GO].state != STATE_FAILED)
	    {
	      /* FIXME: This FAIL is currently disabled as the user can do nothing to correct the problem.
		 The GO compiler itself needs to be fixed to support CET.  */
#if 0
	      fail (data, TEST_ONLY_GO, source, "combining GO and non-GO object files on x86 systems is not safe - it disables CET");
#else
	      skip (data, TEST_ONLY_GO, source, "although mixed GO & C programs are unsafe on x86 (because CET is not supported) this is a GO compiler problem not a program builder problem");
#endif
	    }
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
	 get_filename (data), get_tool_name (tool), version, source);

  if (tool == TOOL_GO)
    {
      if (version == 0)
	{
	  if (tests[TEST_GO_REVISION].enabled
	      && tests[TEST_GO_REVISION].state == STATE_UNTESTED)
	    {
	      /* This is not a MAYB result, because stripped GO binaries can trigger this result.  */
	      einfo (VERBOSE2, "%s: info: GO compilation detected, but version is unknown.  Source: %s",
		     data->filename, source);
	    }
	}
      else if (version < MIN_GO_REVISION)
	{
	  if (tests[TEST_GO_REVISION].enabled
	      && tests[TEST_GO_REVISION].state != STATE_FAILED)
	    {
	      /* Note - in the future MIN_GO_REVISION may no longer be supported by
		 Red Hat even though it is still viable from a security point of view.  */
	      fail (data, TEST_GO_REVISION, source, MIN_GO_REV_STR ("GO revision must be >= ", MIN_GO_REVISION, ""));
	      einfo (VERBOSE, "%s: info: GO compiler revision %u detected in %s",
		     get_filename (data), version, source);
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
	    einfo (VERBOSE2, "%s: info: set binary producer to %s version %u", get_filename (data), get_tool_name (tool), version);
	  else
	    einfo (VERBOSE2, "%s: info: set binary producer to %s", get_filename (data), get_tool_name (tool));
	}

      if (tool == TOOL_GCC) /* FIXME: Update this if glibc ever starts using clang.  */
	per_file.gcc_from_comment = streq (source, COMMENT_SECTION);
    }
  else if (per_file.seen_tools & tool)
    {
      if (per_file.tool_version != version && version > 0)
	{
	  if (per_file.tool_version == 0)
	    {
	      einfo (VERBOSE2, "%s: info: set binary producer to %s version %u", get_filename (data), get_tool_name (tool), version);
	      per_file.tool_version = version;
	    }
	  else if (per_file.tool_version < version)
	    {
	      einfo (VERBOSE, "%s: info: change %s binary producer from version %u to version %u",
		     get_filename (data), get_tool_name (tool), per_file.tool_version, version);
	      per_file.tool_version = version;
	    }
	  else
	    {
	      einfo (VERBOSE2, "%s: info: ignore change in %s binary producer from version %u to version %u",
		     get_filename (data), get_tool_name (tool), per_file.tool_version, version);
	    }
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
		       get_filename (data));
	      per_file.warned_asm_not_gcc = true;
	    }

	  per_file.seen_tools &= ~ TOOL_GCC;
	}

      if (! fixed_format_messages)
	{
	  if (version)
	    einfo (VERBOSE2, "%s: info: set binary producer to %s version %u", get_filename (data), get_tool_name (tool), version);
	  else
	    einfo (VERBOSE2, "%s: info: set binary producer to %s", get_filename (data), get_tool_name (tool));
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
#ifdef DW_LANG_C_plus_plus_03
    case DW_LANG_C_plus_plus_03:
#endif
    case DW_LANG_C_plus_plus_11:
    case DW_LANG_C_plus_plus_14:
      if (! fixed_format_messages)
	einfo (VERBOSE2, "%s: info: Written in C++", get_filename (data));
      set_lang (data, LANG_CXX, SOURCE_DW_AT_LANGUAGE);
      break;

    case DW_LANG_Go:
      set_lang (data, LANG_GO, SOURCE_DW_AT_LANGUAGE);
      break;

#ifdef DW_LANG_Rust
    case DW_LANG_Rust:
#else
      /* BZ 2057737 - User's expect Rust binaries to be identified even
	 if annocheck is built on a system that does not know about Rust.  */
    case 0x1c:
#endif
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
	      einfo (VERBOSE, "%s: info: Written in a language other than C/C++/Go/Rust", get_filename (data));
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

/* Returns true if the current file is a loadable kernel module.
   The heuristic has been copied from eu-elfclassify's is_linux_kernel_module() function.  */

static bool
is_kernel_module (annocheck_data * data)
{
  return elf_kind (data->elf) == ELF_K_ELF
    && per_file.e_type == ET_REL
    && per_file.has_modinfo
    && per_file.has_gnu_linkonce_this_module;
}

static bool
is_grub_module (annocheck_data * data)
{
  return elf_kind (data->elf) == ELF_K_ELF
    && per_file.e_type == ET_REL
    && per_file.has_module_license
    && per_file.has_modname;
}

static inline bool
skip_test (enum test_index check)
{
  if (check < TEST_MAX && ! tests[check].enabled)
    /* We do not issue a SKIP message for disabled tests.  */
    return true;

  return false;
}

static void
parse_dw_at_producer (annocheck_data * data, Dwarf_Attribute * attr)
{
  const char * string = dwarf_formstring (attr);

  if (string == NULL)
    {
      uint form = dwarf_whatform (attr);

      if (form == DW_FORM_GNU_strp_alt)
	{
	  static bool warned = false;

	  if (! warned)
	    {
	      einfo (VERBOSE2, "%s: warn DW_FORM_GNU_strp_alt found in DW_AT_producer, but this form is not yet handled by libelf",
		     get_filename (data));
	      warned = true;
	    }
	}
      else
	warn (data, "DWARF DW_AT_producer attribute uses non-string form");
      /* Keep scanning - there may be another DW_AT_producer attribute.  */
      return;
    }

  einfo (VERBOSE2, "%s: DW_AT_producer = %s", get_filename (data), string);

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
	inform (data, "warn: DW_AT_producer string invalid - probably due to relocations not being applied");
      else
	inform (data, "warn: Unable to determine the binary's producer from it's DW_AT_producer string");
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
      if (skip_test (TEST_OPTIMIZATION))
	;
      else if (strstr (string, " -O2") || strstr (string, " -O3"))
	pass (data, TEST_OPTIMIZATION, SOURCE_DW_AT_PRODUCER, NULL);
      else if (strstr (string, " -O0") || strstr (string, " -O1"))
	/* FIXME: This may not be a failure.  GCC needs -O2 or
	   better for -D_FORTIFY_SOURCE to work properly, but
	   other compilers may not.  */
	fail (data, TEST_OPTIMIZATION, SOURCE_DW_AT_PRODUCER, "optimization level too low");
      else
	info (data, TEST_OPTIMIZATION, SOURCE_DW_AT_PRODUCER, "not found in string");

      if (strstr (string, "-flto"))
	{
	  per_file.lto_used = true;

	  if (! skip_test (TEST_LTO))
	    pass (data, TEST_LTO, SOURCE_DW_AT_PRODUCER, "detected in DWARF information");
	}

      if (skip_test (TEST_PIC))
	;
      else if (strstr (string, " -fpic") || strstr (string, " -fPIC")
	  || strstr (string, " -fpie") || strstr (string, " -fPIE"))
	pass (data, TEST_PIC, SOURCE_DW_AT_PRODUCER, NULL);
      else
	info (data, TEST_PIC, SOURCE_DW_AT_PRODUCER, "-fpic/-fpie not found in string");

      if (skip_test (TEST_STACK_PROT))
	;
      else if (strstr (string, "-fstack-protector-strong")
	  || strstr (string, "-fstack-protector-all"))
	pass (data, TEST_STACK_PROT, SOURCE_DW_AT_PRODUCER, NULL);
      else if (strstr (string, "-fstack-protector"))
	fail (data, TEST_STACK_PROT, SOURCE_DW_AT_PRODUCER, "insufficient protection enabled");
      else
	info (data, TEST_STACK_PROT, SOURCE_DW_AT_PRODUCER, "not found in string");

      if (skip_test (TEST_WARNINGS))
	;
      else if (strstr (string, "-Wall")
	  || strstr (string, "-Wformat-security")
	  || strstr (string, "-Werror=format-security"))
	pass (data, TEST_WARNINGS, SOURCE_DW_AT_PRODUCER, NULL);
      else
	info (data, TEST_WARNINGS, SOURCE_DW_AT_PRODUCER, "not found in string");

      if (skip_test (TEST_GLIBCXX_ASSERTIONS))
	;
      else if (strstr (string, "-D_GLIBCXX_ASSERTIONS")
	       || strstr (string, "-D _GLIBCXX_ASSERTIONS"))
	pass (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_DW_AT_PRODUCER, NULL);
      else
	info (data, TEST_GLIBCXX_ASSERTIONS, SOURCE_DW_AT_PRODUCER, "not found in string");

      if (skip_test (TEST_FORTIFY))
	;
      else if (strstr (string, "-D_FORTIFY_SOURCE=2")
	       || strstr (string, "-D _FORTIFY_SOURCE=2")
	       || strstr (string, "-D_FORTIFY_SOURCE=3")
	       || strstr (string, "-D _FORTIFY_SOURCE=3"))
	pass (data, TEST_FORTIFY, SOURCE_DW_AT_PRODUCER, "found in DW_AT_producer string");
      else
	info (data, TEST_FORTIFY, SOURCE_DW_AT_PRODUCER, "not found in string");

      if (is_x86 ())
	{
	  if (skip_test (TEST_CF_PROTECTION))
	    ;
	  else if (! strstr (string, "-fcf-protection"))
	    info (data, TEST_CF_PROTECTION, SOURCE_DW_AT_PRODUCER, "-fcf-protection option not found in string");
	}
    }
  else if (BE_VERBOSE && ! per_file.warned_command_line)
    {
      inform (data, "info: Command line options not recorded in DWARF DW_AT_producer variable");
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

/* Many glibc binaries are hand built without many of the normal security features.
   This is known and expected however, so detect them here.  */

static bool
is_special_glibc_binary (const char * path)
{
  int i;

  /* If we are testing an uninstalled rpm then the paths will start with "."
     so skip this.  */
  if (path[0] == '.')
    ++path;

  if (path[0] == '/')
    {
      /* If the path is absolute, then strip the prefix.
	 This allows us to cope with symbolic links and 32-bit/64-bit multilibs.  */
      static const char * known_prefixes [] =
	{
	  /* NB/ Keep this array alpha-sorted.  */
	  /* NB/ The terminating forward slash is important.  */
	  "/lib/",
	  "/lib64/",
	  "/sbin/",
	  "/usr/bin/",
	  "/usr/lib/",
	  "/usr/lib/gconv/",
	  "/usr/lib64/",
	  "/usr/lib64/gconv/",
	  "/usr/libexec/",
	  "/usr/libexec/getconf/",
	  "/usr/sbin/"
	};

      for (i = ARRAY_SIZE (known_prefixes); i--;)
	{
	  /* FIXME: To save time we could store the string lengths in the known_prefixes array.  */
	  size_t len = strlen (known_prefixes[i]);
	  int res = strncmp (path, known_prefixes[i], len);

	  if (res == 0)
	    {
	      path += len;
	      break;
	    }
	  /* Do not abort this loop if res > 0/
	     We can have a file like /usr/lib64/libmcheck.a which will
	     not match /usr/lib64/gconv but which should match /usr/lib64.  */
	}

      if (i < 0)
	/* All (absolute) glibc binaries should have a known prefix.  */
	return false;
    }

  const char * known_glibc_specials[] =
    {
      /* NB/ Keep this array alpha sorted.  */
      "ANSI_X3.110.so",
      "ARMSCII-8.so",
      "ASMO_449.so",
      "BIG5.so",
      "BIG5HKSCS.so",
      "BRF.so",
      "CP10007.so",
      "CP1125.so",
      "CP1250.so",
      "CP1251.so",
      "CP1252.so",
      "CP1253.so",
      "CP1254.so",
      "CP1255.so",
      "CP1256.so",
      "CP1257.so",
      "CP1258.so",
      "CP737.so",
      "CP770.so",
      "CP771.so",
      "CP772.so",
      "CP773.so",
      "CP774.so",
      "CP775.so",
      "CP932.so",
      "CSN_369103.so",
      "CWI.so",
      "DEC-MCS.so",
      "EBCDIC-AT-DE-A.so",
      "EBCDIC-AT-DE.so",
      "EBCDIC-CA-FR.so",
      "EBCDIC-DK-NO-A.so",
      "EBCDIC-DK-NO.so",
      "EBCDIC-ES-A.so",
      "EBCDIC-ES-S.so",
      "EBCDIC-ES.so",
      "EBCDIC-FI-SE-A.so",
      "EBCDIC-FI-SE.so",
      "EBCDIC-FR.so",
      "EBCDIC-IS-FRISS.so",
      "EBCDIC-IT.so",
      "EBCDIC-PT.so",
      "EBCDIC-UK.so",
      "EBCDIC-US.so",
      "ECMA-CYRILLIC.so",
      "EUC-CN.so",
      "EUC-JISX0213.so",
      "EUC-JP-MS.so",
      "EUC-JP.so",
      "EUC-KR.so",
      "EUC-TW.so",
      "GB18030.so",
      "GBBIG5.so",
      "GBGBK.so",
      "GBK.so",
      "GEORGIAN-ACADEMY.so",
      "GEORGIAN-PS.so",
      "GOST_19768-74.so",
      "GREEK-CCITT.so",
      "GREEK7-OLD.so",
      "GREEK7.so",
      "HP-GREEK8.so",
      "HP-ROMAN8.so",
      "HP-ROMAN9.so",
      "HP-THAI8.so",
      "HP-TURKISH8.so",
      "IBM037.so",
      "IBM038.so",
      "IBM1004.so",
      "IBM1008.so",
      "IBM1008_420.so",
      "IBM1025.so",
      "IBM1026.so",
      "IBM1046.so",
      "IBM1047.so",
      "IBM1097.so",
      "IBM1112.so",
      "IBM1122.so",
      "IBM1123.so",
      "IBM1124.so",
      "IBM1129.so",
      "IBM1130.so",
      "IBM1132.so",
      "IBM1133.so",
      "IBM1137.so",
      "IBM1140.so",
      "IBM1141.so",
      "IBM1142.so",
      "IBM1143.so",
      "IBM1144.so",
      "IBM1145.so",
      "IBM1146.so",
      "IBM1147.so",
      "IBM1148.so",
      "IBM1149.so",
      "IBM1153.so",
      "IBM1154.so",
      "IBM1155.so",
      "IBM1156.so",
      "IBM1157.so",
      "IBM1158.so",
      "IBM1160.so",
      "IBM1161.so",
      "IBM1162.so",
      "IBM1163.so",
      "IBM1164.so",
      "IBM1166.so",
      "IBM1167.so",
      "IBM12712.so",
      "IBM1364.so",
      "IBM1371.so",
      "IBM1388.so",
      "IBM1390.so",
      "IBM1399.so",
      "IBM16804.so",
      "IBM256.so",
      "IBM273.so",
      "IBM274.so",
      "IBM275.so",
      "IBM277.so",
      "IBM278.so",
      "IBM280.so",
      "IBM281.so",
      "IBM284.so",
      "IBM285.so",
      "IBM290.so",
      "IBM297.so",
      "IBM420.so",
      "IBM423.so",
      "IBM424.so",
      "IBM437.so",
      "IBM4517.so",
      "IBM4899.so",
      "IBM4909.so",
      "IBM4971.so",
      "IBM500.so",
      "IBM5347.so",
      "IBM803.so",
      "IBM850.so",
      "IBM851.so",
      "IBM852.so",
      "IBM855.so",
      "IBM856.so",
      "IBM857.so",
      "IBM858.so",
      "IBM860.so",
      "IBM861.so",
      "IBM862.so",
      "IBM863.so",
      "IBM864.so",
      "IBM865.so",
      "IBM866.so",
      "IBM866NAV.so",
      "IBM868.so",
      "IBM869.so",
      "IBM870.so",
      "IBM871.so",
      "IBM874.so",
      "IBM875.so",
      "IBM880.so",
      "IBM891.so",
      "IBM901.so",
      "IBM902.so",
      "IBM903.so",
      "IBM9030.so",
      "IBM904.so",
      "IBM905.so",
      "IBM9066.so",
      "IBM918.so",
      "IBM921.so",
      "IBM922.so",
      "IBM930.so",
      "IBM932.so",
      "IBM933.so",
      "IBM935.so",
      "IBM937.so",
      "IBM939.so",
      "IBM943.so",
      "IBM9448.so",
      "IEC_P27-1.so",
      "INIS-8.so",
      "INIS-CYRILLIC.so",
      "INIS.so",
      "ISIRI-3342.so",
      "ISO-2022-CN-EXT.so",
      "ISO-2022-CN.so",
      "ISO-2022-JP-3.so",
      "ISO-2022-JP.so",
      "ISO-2022-KR.so",
      "ISO-8859-1_CP037_Z900.so",
      "ISO-IR-197.so",
      "ISO-IR-209.so",
      "ISO646.so",
      "ISO8859-1.so",
      "ISO8859-10.so",
      "ISO8859-11.so",
      "ISO8859-13.so",
      "ISO8859-14.so",
      "ISO8859-15.so",
      "ISO8859-16.so",
      "ISO8859-2.so",
      "ISO8859-3.so",
      "ISO8859-4.so",
      "ISO8859-5.so",
      "ISO8859-6.so",
      "ISO8859-7.so",
      "ISO8859-8.so",
      "ISO8859-9.so",
      "ISO8859-9E.so",
      "ISO_10367-BOX.so",
      "ISO_11548-1.so",
      "ISO_2033.so",
      "ISO_5427-EXT.so",
      "ISO_5427.so",
      "ISO_5428.so",
      "ISO_6937-2.so",
      "ISO_6937.so",
      "JOHAB.so",
      "KOI-8.so",
      "KOI8-R.so",
      "KOI8-RU.so",
      "KOI8-T.so",
      "KOI8-U.so",
      "LATIN-GREEK-1.so",
      "LATIN-GREEK.so",
      "MAC-CENTRALEUROPE.so",
      "MAC-IS.so",
      "MAC-SAMI.so",
      "MAC-UK.so",
      "MACINTOSH.so",
      "MIK.so",
      "Mcrt1.o",
      "NATS-DANO.so",
      "NATS-SEFI.so",
      "POSIX_V6_ILP32_OFF32",
      "POSIX_V6_ILP32_OFFBIG",
      "POSIX_V6_LP64_OFF64",
      "POSIX_V7_ILP32_OFF32",
      "POSIX_V7_ILP32_OFFBIG",
      "POSIX_V7_LP64_OFF64",
      "PT154.so",
      "RK1048.so",
      "SAMI-WS2.so",
      "SHIFT_JISX0213.so",
      "SJIS.so",
      "Scrt1.o",
      "T.61.so",
      "TCVN5712-1.so",
      "TIS-620.so",
      "TSCII.so",
      "UHC.so",
      "UNICODE.so",
      "UTF-16.so",
      "UTF-32.so",
      "UTF-7.so",
      "UTF16_UTF32_Z9.so",
      "UTF8_UTF16_Z9.so",
      "UTF8_UTF32_Z9.so",
      "VISCII.so",    
      "XBS5_ILP32_OFF32",
      "XBS5_ILP32_OFFBIG",
      "XBS5_LP64_OFF64",
      "audit/sotruss-lib.so",
      "build-locale-archive",
      "crt1.o",
      "gcrt1.o",
      "gencat",
      "getconf",
      "getent",
      "grcrt1.o",
      "iconv",
      "iconvconfig",
      "ld-2.33.so",
      "ld-linux-aarch64.so.1",
      "ld-linux-x86-64.so.1",
      "ld-linux-x86-64.so.2",
      "ld-linux.so.2",
      "ld64.so.1",
      "ld64.so.2",
      "ldconfig",
      "libBrokenLocale-2.28.so",
      "libBrokenLocale.so.1",
      "libSegFault.so",
      "libc.so.6",
      "libc_malloc_debug.so.0",
      "libg.a:dummy.o",
      "libm.so.6",
      "libmcheck.a",      
      "libmemusage.so",
      "libmvec.so.1",
      "libnsl.so.1",
      "libnss_compat.so.2",
      "libpcprofile.so",
      "libpthread-2.28.so",
      "libresolv-2.28.so",
      "libresolv.so.2",
      "librt.so.1",
      "libthread_db.so.1",
      "locale",
      "localedef",
      "makedb",
      "memusagestat",
      "pcprofiledump",
      "pldd",
      "rcrt1.o",
      "sprof",
      "zdump",
      "zic"
    };

  for (i = ARRAY_SIZE (known_glibc_specials); i--;)
    {
      int res = strcmp (path, known_glibc_specials[i]);

      if (res == 0)
	return true;
      /* Since the array is alpha-sorted and we are searching in reverse order,
	 a positive result means that path > special and hence we can stop the search.  */
      if (res > 0)
	return false;
    }
  return false;
}

static bool
start (annocheck_data * data)
{
  if (disabled)
    return false;

  if (! full_filename.option_set)
    {
      full_filename.option_value = BE_VERBOSE ? true : false;
      full_filename.option_set = true;
    }

  if (! provide_url.option_set)
    {
      provide_url.option_value = BE_VERBOSE ? true : false;
      provide_url.option_set = true;
    }

  if (! dt_rpath_is_ok.option_set)
    {
#ifdef AARCH64_BRANCH_PROTECTION_SUPPORTED
      dt_rpath_is_ok.option_value = false;
#else
      dt_rpath_is_ok.option_value = true;
#endif
      dt_rpath_is_ok.option_set = true;
    }

  if (! fail_for_all_unicode.option_set)
    {
      switch (current_profile)
	{
	case PROFILE_EL7:
	case PROFILE_EL8:
	case PROFILE_EL9:
	  fail_for_all_unicode.option_value = true;
	  break;
	default:
	  fail_for_all_unicode.option_value = false;
	  break;
	}
      fail_for_all_unicode.option_set = true;
    }

  /* Handle mutually exclusive tests.  */
  if (tests [TEST_BRANCH_PROTECTION].enabled && tests [TEST_NOT_BRANCH_PROTECTION].enabled)
    {
#ifdef AARCH64_BRANCH_PROTECTION_SUPPORTED
      tests [TEST_NOT_BRANCH_PROTECTION].enabled = false;
#else
      tests [TEST_BRANCH_PROTECTION].enabled = false;
#endif
    }

  if (tests [TEST_DYNAMIC_TAGS].enabled && tests [TEST_NOT_DYNAMIC_TAGS].enabled)
    {
#ifdef AARCH64_BRANCH_PROTECTION_SUPPORTED
      tests [TEST_NOT_DYNAMIC_TAGS].enabled = false;
#else
      tests [TEST_DYNAMIC_TAGS].enabled = false;
#endif
    }

  /* (Re) Set the results for the tests.  */
  int i;

  for (i = 0; i < TEST_MAX; i++)
    {
      tests [i].state = STATE_UNTESTED;
      tests [i].result_announced = false;
      tests [i].skipped = false;
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

  /* We do not expect to find ET_EXEC binaries.  These days
     all binaries should be ET_DYN, even executable programs.  */
  if (is_special_glibc_binary (data->full_filename))
    skip (data, TEST_PIE, SOURCE_ELF_HEADER, "glibc binaries do not have to be built for PIE");
  else if (per_file.e_type == ET_EXEC)
    /* Delay generating a FAIL result as GO binaries can SKIP this test,
       but we do not yet know if GO is a producer.  Instead check during
       finish().  */
    ;
  else
    pass (data, TEST_PIE, SOURCE_ELF_HEADER, NULL);

  /* Check to see which tool(s) produced this binary.  */
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

      /* We do not actually need to scan the contents of the .text section.  */
      return false;
    }

  if (tests[TEST_UNICODE].enabled
      && (sec->shdr.sh_type == SHT_SYMTAB
	  || sec->shdr.sh_type == SHT_DYNSYM))
    return true;

  if (per_file.debuginfo_file)
    return false;

  /* If the file has a stack section then check its permissions.  */
  if (streq (sec->secname, ".stack"))
    {
      if ((sec->shdr.sh_flags & (SHF_WRITE | SHF_EXECINSTR)) != SHF_WRITE)
	fail (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, "the .stack section has incorrect permissions");
      else if (tests[TEST_GNU_STACK].state == STATE_PASSED)
	maybe (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, "multiple stack sections detected");
      else
	pass (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, ".stack section exists and has correction permissions");

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
	    skip (data, TEST_WRITABLE_GOT, SOURCE_SECTION_HEADERS, "Object file");
	  else
	    fail (data, TEST_WRITABLE_GOT, SOURCE_SECTION_HEADERS, "the GOT/PLT relocs are writable");
	}
      else
	pass (data, TEST_WRITABLE_GOT, SOURCE_SECTION_HEADERS, NULL);
	
      return false;
    }

  if (streq (sec->secname, ".modinfo"))
    per_file.has_modinfo = true;

  if (streq (sec->secname, ".gnu.linkonce.this_module"))
    per_file.has_gnu_linkonce_this_module = true;

  if (streq (sec->secname, ".module_license"))
    per_file.has_module_license = true;

  if (streq (sec->secname, ".modname"))
    per_file.has_modname = true;

  if (is_object_file () && streq (sec->secname, ".note.GNU-stack"))
    {
      /* The permissions of the .note-GNU-stack section are used to set the permissions of the GNU_STACK segment,
	 hence they should not include SHF_EXECINSTR.  Note - if the section is missing, then the linker may
	 choose to create an executable stack (based upon command line options, amoungst other things) so it is
	 always best to specify this section.  */
      if (sec->shdr.sh_flags & SHF_EXECINSTR)
	fail (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, ".note.GNU-stack section has execute permission");
      else
	pass (data, TEST_GNU_STACK, SOURCE_SECTION_HEADERS, "non-executable .note.GNU-stack section found");
      return false;
    }

  if (sec->shdr.sh_size == 0)
    return false;

  if (streq (sec->secname, ".comment"))
    return true;

  if (streq (sec->secname, ".gnu.attributes"))
    return true;

  if (streq (sec->secname, ".rodata"))
    /* We might want to scan this section for a GO version string.  */
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

  if (sym == NULL || * sym == 0)
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
  if (per_file.note_source[producer] == version)
    return;

  per_file.note_source[producer] = version;

  if (fixed_format_messages)
    return;

  if (! BE_VERY_VERBOSE)
    return;

  einfo (PARTIAL, "%s: %s: info: notes produced by %s plugin ",
	 HARDENED_CHECKER_NAME, get_filename (data), source);

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

/* Returns true iff COMPONENT_NAME is in FUNC_NAMES[NUM_NAMES].  */

static bool
skip_this_func (const char ** func_names, unsigned int num_names, const char * component_name)
{
  unsigned int i;

  for (i = num_names; i--;)
    {
      int res = strcmp (component_name, func_names[i]);

      if (res == 0)
	return true;

      if (res > 0)
	/* The array is alpha-sorted, and we are scanning in reverse... */
	break;
    }

  return false;
}

static char reason[1280]; /* FIXME: Use a dynamic buffer ? */

static bool
skip_fortify_checks_for_function (annocheck_data * data, enum test_index check, const char * component_name)
{
  /* Save time by checking for any function that starts with __.  */
  if (component_name[0] == '_' && component_name[1] == '_')
    return true;

  const static char * non_fortify_funcs[] =
    {
      /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
      "_GLOBAL__sub_I_main",
      "_Unwind_Resume",
      "_dl_relocate_static_pie",     /* Found in x86_64, RHEL-9, podman-catonit.  */
      "_dl_start",
      "_dl_start_user", 	     /* Found in ppc64le, RHEL-9, /lib64/ld64.so.2.  */
      "_dl_tunable_set_arena_max",   /* Found in ppc64le, RHEL-9, /lib64/libc_malloc_debug.so.0.  */
      "_nl_finddomain_subfreeres",
      "_nl_unload_domain",
      "_nss_compat_initgroups_dyn",
      "_nss_compat_setgrent",
      "_nss_dns_getcanonname_r",
      "_nss_dns_gethostbyname3_r",
      "_nss_files_parse_protoent",
      "_nss_files_sethostent",
      "_start",
      "abort",
      "blacklist_store_name",
      "buffer_free",
      "cabsf128",
      "call_fini",
      "check_match",		     /* Found in aarch64, RHEL-8, ld-2.28.so.  */
      "check_one_fd",		     /* Found in libc.a(check_fds.o).  */
      "dlmopen_doit",                /* Found in ppc64le, RHEL-9, /lib64/ld64.so.2.  */
      "feraiseexcept",
      "fini",
      "free_derivation",
      "free_mem",
      "free_res",
      "gai_cancel",
      "gai_suspend",
      "getaddrinfo_a",
      "handle_zhaoxin",		     /* Found in libc.a(libc-start.o).  */
      "install_handler",
      "internal_setgrent",
      "j0l",
      "j1f64",
      "login",
      "logwtmp",
      "matherr",
      "rtld_lock_default_lock_recursive",  /* Found in aarch64, RHEL-8, ld-2.28.so.  */
      "td_init",	             /* Found in ppc64le, RHEL-9, /lib64/libthread_db.so.1.  */
      "td_log",
      "td_ta_map_lwp2thr",
      "td_thr_validate",
      "unlink_blk" 	             /* Found in ppc64le, RHEL-9, /lib64/libc_malloc_debug.so.0.  */
    };

  if (skip_this_func (non_fortify_funcs, ARRAY_SIZE (non_fortify_funcs), component_name))
    {
      sprintf (reason, "\
function %s is part of the C library, and as such it does not need fortification",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, reason);
      return true;
    }

  return false;
}

static bool
skip_pic_checks_for_function (annocheck_data * data, enum test_index check, const char * component_name)
{
  const static char * non_pie_funcs[] =
    {
      /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
      "_GLOBAL__sub_I_main",
      "_Unwind_Resume",
      "__errno_location",
      "__libc_start_call_main",
      "__tls_get_offset",
      "_nl_finddomain_subfreeres",
      "_start",
      "abort",
      "atexit",                  /* The atexit function in libiberty is only compiled with -fPIC not -fPIE.  */
      "check_one_fd",
      "free_mem"
    };

  if (skip_this_func (non_pie_funcs, ARRAY_SIZE (non_pie_funcs), component_name))
    {
      sprintf (reason, "\
function %s is used to start/end program execution and as such does not need to compiled with PIE support",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, reason);
      return true;
    }

  return false;
}

static bool
skip_stack_checks_for_function (annocheck_data * data, enum test_index check, const char * component_name)
{
  /* Note - this list has been developed over time in response to bug reports.
     It does not have a well defined set of criteria for name inclusion.  */
  const static char * startup_funcs[] =
    { /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
      "../sysdeps/x86_64/crti.S",
      "../sysdeps/x86_64/start.S",
      "_GLOBAL__sub_I_main",
      "_ZN12_GLOBAL__N_122thread_cleanup_handlerEPv", /* Found in Clang's compile-rt library.  */
      "__libc_csu_fini",
      "__libc_csu_init",
      "__libc_init_first",
      "__libc_setup_tls",
      "__libc_start_call_main",    /* Found in ppc64le, RHEL-9, /lib64/libc.so.6.  */
      "__libc_start_main",
      "__libgcc_s_init",   /* Found in i686 RHEL-8 /lib/libc-2.28.so.  */
      "__syscall_error",  /* Found in i686 RHEL-8 /lib/libc-2.28.so.  */
      "_dl_cache_libcmp", /* Found in s390x, RHEL-8, /lib64/ld-2.28.so.  */
      "_dl_relocate_static_pie",
      "_dl_start",
      "_dl_start_user", /* Found in ppc64le, RHEL-9 /lib64/ld64.so.2.  */
      "_dl_sysinfo_int80", /* In /lib/ld-linux.so.2.  */
      "_dl_tls_static_surplus_init",
      "_fini",
      "_init",
      "_start",
      "check_match", 	/* Found in AArch64, RHEL-8, /lib64/ld-2.28.so.  */
      "check_one_fd",
      "dlmopen_doit",
      "get_common_indices.constprop.0",
      "is_dst",
      "notify_audit_modules_of_loaded_object",
      "static_reloc.c"
    };

  if (skip_this_func (startup_funcs, ARRAY_SIZE (startup_funcs), component_name))
    {
      sprintf (reason, "\
function %s is part of the C library's startup code, which executes before stack protection is established",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, reason);
      return true;
    }

  /* The function used to check for stack checking do not pass these tests either.  */
  const static char * stack_check_funcs[] =
    { /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
      "__stack_chk_fail_local",
      "stack_chk_fail_local.c"
    };

  if (skip_this_func (stack_check_funcs, ARRAY_SIZE (stack_check_funcs), component_name))
    {
      sprintf (reason, "\
function %s is part of the stack checking code and as such does not need stack protection itself",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, reason);
      return true;
    }

  /* Functions generated by the linker do not use stack protection.  */
  const static char * linker_funcs[] =
    { /* NB. KEEP THIS ARRAY ALPHA-SORTED  */
      "__tls_get_offset"
    };

  if (skip_this_func (linker_funcs, ARRAY_SIZE (linker_funcs), component_name))
    {
      sprintf (reason, "\
function %s is generated by the linker and as such does not use stack protection",
	       component_name);
      skip (data, check, SOURCE_SKIP_CHECKS, reason);
      return true;
    }

  return false;
}

/* Decides if a given test should be skipped for a the current component.
   If it should be skipped then a SKIP result is generated.  */

static bool
skip_test_for_current_func (annocheck_data * data, enum test_index check)
{
  /* BZ 1923439: IFuncs are compiled without some of the security
     features because they execute in a special enviroment.  */
  if (ELF64_ST_TYPE (per_file.component_type) == STT_GNU_IFUNC)
    {
      switch (check)
	{
	case TEST_FORTIFY:
	case TEST_STACK_CLASH:
	case TEST_STACK_PROT:
	  sprintf (reason, "code at %#lx is a part of an ifunc", per_file.note_data.start);
	  skip (data, check, SOURCE_SKIP_CHECKS, reason);
	  return true;
	default:
	  break;
	}
    }

  if (is_special_glibc_binary (data->full_filename))
    {
      sprintf (reason, "the %s binary is a special case, hand-crafted by the glibc build system", data->filename);
      skip (data, check < TEST_MAX ? check : TEST_NOTES, SOURCE_SKIP_CHECKS, reason);
      return true;
    }

  const char * component_name = per_file.component_name;

  if (component_name == NULL)
    return false;

  if (startswith (component_name, "component: "))
    component_name += strlen ("component: ");

  if (streq (component_name, "elf_init.c")
      || streq (component_name, "init.c"))
    {
      sprintf (reason, "\
function %s is part of the C library's startup code, which executes before a security framework is established",
	       component_name);
      skip (data, check < TEST_MAX ? check : TEST_NOTES, SOURCE_SKIP_CHECKS, reason);
      return true;
    }

  switch (check)
    {
    case TEST_STACK_PROT:
    case TEST_STACK_CLASH:
    case TEST_STACK_REALIGN:
      return skip_stack_checks_for_function (data, check, component_name);

    case TEST_PIC:
    case TEST_PIE:
      return skip_pic_checks_for_function (data, check, component_name);

    case TEST_FORTIFY:
      return skip_fortify_checks_for_function (data, check, component_name);

    default:
      return false;
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
      einfo (FAIL, "%s: Unrecognised annobin note type %d", get_filename (data), note->n_type);
      return false;
    }

  prefer_func_name = note->n_type == NT_GNU_BUILD_ATTRIBUTE_FUNC;
  note_data = & per_file.note_data;

  if (note->n_namesz < 3)
    {
      einfo (FAIL, "%s: Corrupt annobin note, name size: %x", get_filename (data), note->n_namesz);
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
		 get_filename (data), note->n_descsz);
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
		     get_filename (data), start, end);
	      return true;
	    }
	}

      if (end == (ulong) -1)
	{
	  einfo (WARN, "%s: Corrupt annobin note : end address == -1", get_filename (data));
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
	  /* The range has changed.  */

	  /* Update the saved range.  */
	  per_file.note_data.start = start;
	  per_file.note_data.end = end;

	  /* If the new range is valid, get a component name for it.  */
	  if (start != end)
	    get_component_name (data, sec, note_data, prefer_func_name);
	}
    }

  if (name_offset >= sec->data->d_size)
    goto corrupt_note;

  const char *  namedata = sec->data->d_buf + name_offset;
  uint          bytes_left = sec->data->d_size - name_offset;

  if (bytes_left < 1 || note->n_namesz > bytes_left)
    goto corrupt_note;

  uint pos = (namedata[0] == 'G' ? 3 : 1);
  if (pos > bytes_left)
    goto corrupt_note;

  char          attr_type = namedata[pos - 1];
  const char *  attr = namedata + pos;

  /* Advance pos to the attribute's value.  */
  if (! isprint (* attr))
    pos ++;
  else
    pos += strnlen (namedata + pos, bytes_left - pos) + 1;

  if (pos > bytes_left)
    goto corrupt_note;

  /* If we have a new range and we have previously seen a tool note then apply it to
     the region that we are about to scan, unless the note that we are about to parse
     is itself a tool note.  */
  if (note->n_descsz > 0
      && per_file.current_tool != TOOL_UNKNOWN
      && * attr != GNU_BUILD_ATTRIBUTE_VERSION)
    add_producer (data, per_file.current_tool, per_file.tool_version, SOURCE_ANNOBIN_NOTES, false);

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
	else if (bytes < 0)
	  goto corrupt_note;

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

  /* We skip notes with empty ranges unless we are dealing with unrelocated
     object files or version notes.  We always parse version notes so that
     we always know which tool produced the notes that follow.  */
  if (! is_object_file ()
      && note_data->start == note_data->end
      && * attr != GNU_BUILD_ATTRIBUTE_VERSION)
    {
      einfo (VERBOSE2, "skip %s note for zero-length range at %#lx",
	     note_name (attr), note_data->start);
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
	       get_filename (data), SPEC_VERSION, * attr - '0');

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
	  if (note_data->start < note_data->end)
	    per_file.seen_tools_with_code |= TOOL_GAS;
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
	  if (note_data->start < note_data->end)
	    per_file.seen_tools_with_code |= TOOL_GCC;
	  break;

	case ANNOBIN_TOOL_ID_GCC_LTO:
	  name = "lto";
	  if (version > 99)
	    add_producer (data, TOOL_GIMPLE, version / 100, SOURCE_ANNOBIN_NOTES, true);
	  else
	    add_producer (data, TOOL_GIMPLE, 0, SOURCE_ANNOBIN_NOTES, true);
	  if (! skip_test (TEST_LTO))
	    pass (data, TEST_LTO, SOURCE_ANNOBIN_NOTES, "detected in version note");
	  if (note_data->start < note_data->end)
	    per_file.seen_tools_with_code |= TOOL_GCC;
	  per_file.lto_used = true;
	  break;

	case ANNOBIN_TOOL_ID_LLVM:
	  name = "LLVM";
	  if (version > 99)
	    add_producer (data, TOOL_LLVM, version / 100, SOURCE_ANNOBIN_NOTES, true);
	  else
	    add_producer (data, TOOL_LLVM, 0, SOURCE_ANNOBIN_NOTES, true);
	  if (note_data->start < note_data->end)
	    per_file.seen_tools_with_code |= TOOL_LLVM;
	  break;

	case ANNOBIN_TOOL_ID_CLANG:
	  name = "Clang";
	  if (version > 99)
	    add_producer (data, TOOL_CLANG, version / 100, SOURCE_ANNOBIN_NOTES, true);
	  else
	    add_producer (data, TOOL_CLANG, 0, SOURCE_ANNOBIN_NOTES, true);
	  if (note_data->start < note_data->end)
	    per_file.seen_tools_with_code |= TOOL_CLANG;
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

	  /* Look for an (optional) date string after the version numbers.  */
	  uint dummy, date;
	  if (sscanf (attr + 1 + strlen (t->lead_in), "%u.%u.%u %u", & dummy, & dummy, & dummy, & date) == 4)
	    per_file.gcc_date = date;

	  einfo (VERBOSE2, "%s: info: detected information created by an annobin plugin running on %s version %u.%u.%u",
		 get_filename (data), t->tool_name, major, minor, rel);

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
		     get_filename (data), t->tool_name, per_file.run_major, major);
	      if (per_file.run_major < major)
		per_file.run_major = major;
	    }

	  if (per_file.anno_major != 0 && per_file.anno_major != per_file.run_major)
	    {
	      if (! per_file.warned_version_mismatch)
		{
		  warn (data, "The annobin plugin was built by a compiler with a different major version to the one upon which it was run");
		  einfo (VERBOSE, "debug: Annobin plugin built by %s version %u but run on %s version %u",
			 t->tool_name, per_file.anno_major,
			 t->tool_name, per_file.run_major);
		  per_file.warned_version_mismatch = true;
		}
	    }

	  per_file.run_minor = minor;
	  per_file.run_rel = rel;

	  if (per_file.anno_major != 0
	      && (per_file.anno_minor != minor || per_file.anno_rel != rel))
	    {
	      if (! per_file.warned_version_mismatch)
		{
		  if (per_file.anno_minor > minor)
		    warn (data, "The annobin plugin was built to run on a newer version of the compiler");
		  else if (per_file.anno_minor < minor)
		    inform (data, "warn: The annobin plugin was built by an older version of the compiler");
		  else if (per_file.anno_rel > rel)
		    warn (data, "The annobin plugin was built to run on a newer version of the compiler");
		  else
		    inform (data, "warn: The annobin  plugin was built by an older version of the compiler");

		  einfo (VERBOSE, "debug: Annobin plugin was built by %s %u.%u.%u but run on %s version %u.%u.%u",
			 t->tool_name, per_file.anno_major, per_file.anno_minor, per_file.anno_rel,
			 t->tool_name, per_file.run_major, per_file.run_minor, per_file.run_rel);
		  einfo (VERBOSE, "debug: If there are WARN or FAIL results that appear to be incorrect, it could be due to this discrepancy.");

		  per_file.warned_version_mismatch = true;
		}
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

	  /* Look for an (optional) date string after the version numbers.  */
	  uint dummy, date;
	  if (sscanf (attr + 1 + strlen (t->lead_in), "%u.%u.%u %u", & dummy, & dummy, & dummy, & date) == 4)
	    per_file.annobin_gcc_date = date;

	  einfo (VERBOSE2, "%s: info: detected information stored by an annobin plugin built by %s version %u.%u.%u",
		 get_filename (data), t->tool_name, major, minor, rel);

	  if (per_file.anno_major == 0)
	    {
	      per_file.anno_major = major;
	    }
	  else if (per_file.anno_major != major)
	    {
	      einfo (INFO, "%s: WARN: notes produced by annobins compiled for more than one version of %s (%u vs %u)",
		     get_filename (data), t->tool_name, per_file.anno_major, major);
	      if (per_file.anno_major < major)
		per_file.anno_major = major;
	    }

	  if (per_file.run_major != 0 && per_file.run_major != per_file.anno_major)
	    {
	      if (! per_file.warned_version_mismatch)
		{
		  einfo (INFO, "%s: WARN: Annobin plugin was built by %s version %u but run on %s version %u",
			 get_filename (data), t->tool_name, per_file.anno_major, t->tool_name, per_file.run_major);
		  per_file.warned_version_mismatch = true;
		}
	    }

	  per_file.anno_minor = minor;
	  per_file.anno_rel = rel;

	  if (per_file.run_major != 0
	      && (per_file.run_minor != minor || per_file.run_rel != rel))
	    {
	      if (! per_file.warned_version_mismatch)
		{
		  if (per_file.run_minor < minor)
		    warn (data, "The annobin plugin was built to run on a newer version of the compiler");
		  else if (per_file.run_minor > minor)
		    inform (data, "warn: The annobin plugin was built by an older version of the compiler");
		  else if (per_file.run_rel < rel)
		    warn (data, "The annobin plugin was built to run on a newer version of the compiler");
		  else
		    inform (data, "warn: The annobin  plugin was built by an older version of the compiler");

		  einfo (VERBOSE, "debug: Annobin plugin was built by %s %u.%u.%u but run on %s version %u.%u.%u",
			 t->tool_name, major, minor, rel,
			 t->tool_name, per_file.run_major, per_file.run_minor, per_file.run_rel);
		  einfo (VERBOSE, "debug: If there are WARN or FAIL results that appear to be incorrect, it could be due to this discrepancy.");

		  per_file.warned_version_mismatch = true;
		}
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
		 get_filename (data), per_file.component_name, version);
	}
      else if (strstr (attr + 1, "plugin name"))
	{
	  einfo (VERBOSE2, "%s: info: %s",
		 get_filename (data), attr + 1);
	}
      else
	einfo (VERBOSE, "%s: info: unable to parse tool attribute: %s",
	       get_filename (data), attr + 1);
      break;

    case GNU_BUILD_ATTRIBUTE_PIC:
      if (skip_test (TEST_PIC))
	break;

      /* Convert the pic value into a pass/fail result.  */
      switch (value)
	{
	case -1:
	default:
	  if (! skip_test_for_current_func (data, TEST_PIC))
	    {
	      maybe (data, TEST_PIC, SOURCE_ANNOBIN_NOTES, "unexpected value");
	      einfo (VERBOSE2, "debug: PIC note value: %x", value);
	    }
	  break;

	case 0:
	  if (! skip_test_for_current_func (data, TEST_PIC))
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
      if (skip_test (TEST_STACK_PROT))
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
	  if (! skip_test_for_current_func (data, TEST_STACK_PROT))
	    maybe (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	  break;

	case 0: /* NONE */
	  /* See BZ 1923439: Parts of glibc are deliberately compiled without stack protection,
	     because they execute before the framework is established.  This is currently handled
	     by tests in skip_check ().  */
	  if (! skip_test_for_current_func (data, TEST_STACK_PROT))
	    fail (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "stack protection deliberately disabled");
	  break;

	case 1: /* BASIC (funcs using alloca or with local buffers > 8 bytes) */
	case 4: /* EXPLICIT */
	  if (! skip_test_for_current_func (data, TEST_STACK_PROT))
	    fail (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "only some functions protected");
	  break;

	case 2: /* ALL */
	case 3: /* STRONG */
	  pass (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, NULL);
	  break;
	}
      break;

    case GNU_BUILD_ATTRIBUTE_SHORT_ENUM:
      if (skip_test (TEST_SHORT_ENUMS))
	break;

      enum short_enum_state state = value ? SHORT_ENUM_STATE_SHORT : SHORT_ENUM_STATE_LONG;

      if (value > 1)
	{
	  maybe (data, TEST_SHORT_ENUMS, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	  einfo (VERBOSE2, "debug: enum note value: %x", value);
	}
      else if (per_file.short_enum_state == SHORT_ENUM_STATE_UNSET)
	per_file.short_enum_state = state;
      else if (per_file.short_enum_state != state)
	fail (data, TEST_SHORT_ENUMS, SOURCE_ANNOBIN_NOTES, "both short and long enums supported");
      break;

    case 'b':
      if (startswith (attr, "branch_protection:"))
	{
	  if (per_file.e_machine != EM_AARCH64)
	    /* FIXME: A branch protection note for a non AArch64 binary is suspicious...  */
	    break;

	  if (skip_test (TEST_BRANCH_PROTECTION) && skip_test (TEST_NOT_BRANCH_PROTECTION))
	    break;

	  attr += strlen ("branch_protection:");
	  if (* attr == 0
	      || streq (attr, "(null)")
	      || streq (attr, "default")
	      || streq (attr, "none"))
	    {
	      fail (data, TEST_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, "not enabled");
	      pass (data, TEST_NOT_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, "disabled");
	    }
	  else if (streq (attr, "bti+pac-ret")
		   || streq (attr, "standard")
		   || startswith (attr, "pac-ret+bti"))
	    {
	      pass (data, TEST_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, "protection enabled");
	      fail (data, TEST_NOT_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, "protection enabled");
	    }
	  else if (streq (attr, "bti")
		   || startswith (attr, "pac-ret"))
	    {
	      fail (data, TEST_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, "only partially enabled");
	      fail (data, TEST_NOT_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, "only partially disabled");
	    }
	  else
	    {
	      maybe (data, TEST_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      maybe (data, TEST_NOT_BRANCH_PROTECTION, SOURCE_ANNOBIN_NOTES, "unexpected note value");
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

	  if (skip_test (TEST_CF_PROTECTION))
	    break;

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
	      if (tests[TEST_PROPERTY_NOTE].enabled)
		/* Do not PASS here.  The binary might be linked with other objects which do
		   not have this option enabled, and so the property note will not be correct.
		   See BZ 1991943 and 2010692.  */
		;
	      else
		pass (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "branch protection enabled.");
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
	      /* Sadly there was an annobin/gcc sync issue with the 20211019 gcc, which lead to
		 corrupt data being recorded by the annobin plugin.  */
	      if (per_file.annobin_gcc_date == per_file.gcc_date
		  && per_file.gcc_date == 20211019)
		skip (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "bad data recorded by annobin plugin");
	      else
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
	  if (skip_test (TEST_FORTIFY))
	    break;

	  switch (value)
	    {
	    case -1:
	    default:
	      if (! skip_test_for_current_func (data, TEST_FORTIFY))
		{
		  maybe (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "unexpected note value");
		  einfo (VERBOSE2, "debug: fortify note value: %x", value);
		}
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
	      else if (is_special_glibc_binary (data->full_filename))
		skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "glibc binaries are built without fortification");		
	      else if (! skip_test_for_current_func (data, TEST_FORTIFY))
		fail (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "-D_FORTIFY_SOURCE=2 was not present on the command line");
	      break;

	    case 0:
	    case 1:
	      if (is_special_glibc_binary (data->full_filename))
		skip (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "glibc binaries are built without fortification");		
	      else if (! skip_test_for_current_func (data, TEST_FORTIFY))
		fail (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "-O level is too low");
	      break;

	    case 2:
	    case 3:
	      pass (data, TEST_FORTIFY, SOURCE_ANNOBIN_NOTES, "fortify note found");
	      break;
	    }
	}
      else
	einfo (VERBOSE2, "Unsupported annobin note '%s' - ignored", attr);
      break;

    case 'G':
      if (streq (attr, "GOW"))
	{
	  if (skip_test (TEST_OPTIMIZATION))
	    ;
	  else if (value == -1)
	    {
	      maybe (data, TEST_OPTIMIZATION, SOURCE_ANNOBIN_NOTES, "unexpected note value");
	      einfo (VERBOSE2, "debug: optimization note value: %x", value);
	    }
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

	  if (skip_test (TEST_WARNINGS))
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


	  if (skip_test (TEST_LTO))
	    {
	      if (value & (1 << 16))
		per_file.lto_used = true;
	    }
	  else if (value & (1 << 16))
	    {
	      if (value & (1 << 17))
		fail (data, TEST_LTO, SOURCE_ANNOBIN_NOTES, "compiled with both -flto and -fno-lto");
	      else
		pass (data, TEST_LTO, SOURCE_ANNOBIN_NOTES, "LTO compilation detected");
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
	  if (skip_test (TEST_GLIBCXX_ASSERTIONS))
	    break;

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
      if (startswith (attr, "INSTRUMENT:"))
	{
	  if (skip_test (TEST_INSTRUMENTATION))
	    break;

	  if (! per_file.warned_about_instrumentation)
	    {
	      einfo (INFO, "%s: WARN: (%s): Instrumentation enabled - this is probably a mistake for production binaries",
		     get_filename (data), per_file.component_name);

	      per_file.warned_about_instrumentation = true;

	      if (BE_VERBOSE)
		{
		  uint sanitize, instrument, profile, arcs;

		  attr += strlen ("INSTRUMENT:");
		  if (sscanf (attr, "%u/%u/%u/%u", & sanitize, & instrument, & profile, & arcs) != 4)
		    {
		      einfo (VERBOSE2, "%s: ICE:  (%s): Unable to extract details from instrumentation note",
			     get_filename (data), per_file.component_name);
		    }
		  else
		    {
		      einfo (VERBOSE, "%s: info: (%s):  Details: -fsanitize=...: %s",
			     get_filename (data), per_file.component_name, sanitize ? "enabled" : "disabled");
		      einfo (VERBOSE, "%s: info: (%s):  Details: -finstrument-functions: %s",
			     get_filename (data), per_file.component_name, instrument ? "enabled" : "disabled");
		      einfo (VERBOSE, "%s: info: (%s):  Details: -p and/or -pg: %s",
			     get_filename (data), per_file.component_name, profile ? "enabled" : "disabled");
		      einfo (VERBOSE, "%s: info: (%s):  Details: -fprofile-arcs: %s",
			     get_filename (data), per_file.component_name, arcs ? "enabled" : "disabled");
		    }
		}
	      else
		einfo (INFO, "%s: info: (%s):  Run with -v for more information",
		       get_filename (data), per_file.component_name);
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

	  if (skip_test (TEST_STACK_CLASH))
	    break;

	  switch (value)
	    {
	    case 0:
	      if (! skip_test_for_current_func (data, TEST_STACK_CLASH))
		{
		  /* Sadly there was an annobin/gcc sync issue with the 20211019 gcc, which lead to
		     corrupt data being recorded by the annobin plugin.  */
		  if (per_file.annobin_gcc_date == per_file.gcc_date
		      && per_file.gcc_date == 20211019)
		    skip (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, "bad data recorded by annobin plugin");
		  else
		    fail (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, "-fstack-clash-protection not enabled");
		}
	      break;

	    case 1:
	      pass (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, NULL);
	      break;

	    default:
	      if (! skip_test_for_current_func (data, TEST_STACK_CLASH))
		{
		  maybe (data, TEST_STACK_CLASH, SOURCE_ANNOBIN_NOTES, "unexpected note value");
		  einfo (VERBOSE2, "debug: stack clash note vbalue: %x", value);
		}
	      break;
	    }
	}
      else if (streq (attr, "stack_realign"))
	{
	  if (per_file.e_machine != EM_386)
	    break;

	  if (skip_test (TEST_STACK_REALIGN))
	    break;

	  switch (value)
	    {
	    default:
	      if (! skip_test_for_current_func (data, TEST_STACK_REALIGN))
		{
		  maybe (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_NOTES, "unexpected note value");
		  einfo (VERBOSE2, "debug: stack realign note vbalue: %x", value);
		}
	      break;

	    case 0:
	      if (! skip_test_for_current_func (data, TEST_STACK_REALIGN))
		fail (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_NOTES, "-mstackrealign not enabled");
	      break;

	    case 1:
	      pass (data, TEST_STACK_REALIGN, SOURCE_ANNOBIN_NOTES, NULL);
	      break;
	    }
	}
      else if (streq (attr, "sanitize_cfi"))
	{
	  if (skip_test (TEST_CF_PROTECTION))
	    ;
	  else if (value < 1)
	    fail (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, "insufficient Control Flow sanitization");
	  else /* FIXME: Should we check that specific sanitizations are enabled ?  */
	    pass (data, TEST_CF_PROTECTION, SOURCE_ANNOBIN_NOTES, NULL);
	  break;
	}
      else if (streq (attr, "sanitize_safe_stack"))
	{
	  if (skip_test (TEST_STACK_PROT))
	    ;
	  else if (value < 1)
	    {
	      if (! skip_test_for_current_func (data, TEST_STACK_PROT))
		fail (data, TEST_STACK_PROT, SOURCE_ANNOBIN_NOTES, "insufficient Stack Safe sanitization");
	    }
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

 corrupt_note:
  einfo (FAIL, "%s: Corrupt annobin note", get_filename (data));
  return false;
}

static void
ffail (annocheck_data * data, const char * message, int level)
{
  if (! report_future_fail)
    level = VERBOSE2;

  einfo (level, "%s: look: %s", get_filename (data), message);
  einfo (level, "%s: ^^^^:  This test is not yet enabled, but if it was enabled, it would fail...",
	 get_filename (data));
}

static void
future_fail (annocheck_data * data, const char * message)
{
  ffail (data, message, INFO);
}

#if 0
static void
vfuture_fail (annocheck_data * data, const char * message)
{
  ffail (data, message, VERBOSE);
}
#endif

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
      einfo (VERBOSE2, "%s: debug: property note type %lx", get_filename (data), type);
      return "unexpected property note type";
    }

  if (size != 4)
    {
      einfo (VERBOSE2, "debug: data note at offset %lx has size %lu, expected 4",
	     (long)(notedata - (const unsigned char *) sec->data->d_buf), size);
      return "the property note data has an invalid size";
    }

  ulong property = get_4byte_value (notedata);

  if ((property & GNU_PROPERTY_AARCH64_FEATURE_1_BTI) == 0)
    {
      if (tests[TEST_BRANCH_PROTECTION].enabled)
	return "the BTI property is not enabled";
    }

  if ((property & GNU_PROPERTY_AARCH64_FEATURE_1_PAC) == 0)
    {
#if 0
      if (tests[TEST_BRANCH_PROTECTION].enabled)
	return "the PAC property is not enabled";
#else
      future_fail (data, "PAC property is not enabled");
#endif
    }

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
      einfo (VERBOSE2, "%s: Ignoring property note type %lx", get_filename (data), type);
      return NULL;
    }

  if (size != 4)
    {
      einfo (VERBOSE2, "debug: data note at offset %lx has size %lu, expected 4",
	     (long)(notedata - (const unsigned char *) sec->data->d_buf), size);
      return "the property note data has an invalid size";
    }

  ulong property = get_4byte_value (notedata);

  if ((property & GNU_PROPERTY_X86_FEATURE_1_IBT) == 0)
    {
      einfo (VERBOSE2, "debug: property bits = %lx", property);
      return "the IBT property is not enabled";
    }

  if ((property & GNU_PROPERTY_X86_FEATURE_1_SHSTK) == 0)
    {
      einfo (VERBOSE2, "debug: property bits = %lx", property);
      return "the SHSTK property is not enabled";
    }

  pass (data, TEST_CF_PROTECTION, SOURCE_PROPERTY_NOTES, "correct flags found in .note.gnu.property note");
  per_file.has_cf_protection = true;
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

  if (skip_test (TEST_PROPERTY_NOTE))
    return true;

  if (note->n_type != NT_GNU_PROPERTY_TYPE_0)
    {
      einfo (VERBOSE2, "%s: info: unexpected GNU Property note type %x", get_filename (data), note->n_type);
      return true;
    }

  if (is_executable ())
    {
      /* More than one note in an executable is an error.  */
      if (tests[TEST_PROPERTY_NOTE].state == STATE_PASSED)
	{
	  /* The loader will only process the first note, so having more than one is an error.  */
	  reason = "there is more than one GNU Property note";
	  goto fail;
	}
    }

  if (note->n_namesz != sizeof ELF_NOTE_GNU
      || strncmp ((char *) sec->data->d_buf + name_offset, ELF_NOTE_GNU, strlen (ELF_NOTE_GNU)) != 0)
    {
      reason = "the property note does not have expected name";
      einfo (VERBOSE2, "debug: Expected name '%s', got '%.*s'", ELF_NOTE_GNU,
	     (int) strlen (ELF_NOTE_GNU), (char *) sec->data->d_buf + name_offset);
      goto fail;
    }

  uint expected_quanta = data->is_32bit ? 4 : 8;
  if (note->n_descsz < 8 || (note->n_descsz % expected_quanta) != 0)
    {
      reason = "the property note data has the wrong size";
      einfo (VERBOSE2, "debug: Expected data size to be a multiple of %d but the size is 0x%x",
	     expected_quanta, note->n_descsz);
      goto fail;
    }

  uint remaining = note->n_descsz;
  const unsigned char * notedata = sec->data->d_buf + data_offset;
  if (is_x86 () && remaining == 0)
    {
      reason = "the note section is present but empty";
      goto fail;
    }

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
      einfo (VERBOSE2, "%s: WARN: Property notes for architecture %d not handled", get_filename (data), per_file.e_machine);
      return true;
    }

  while (remaining)
    {
      ulong type = get_4byte_value (notedata);
      ulong size = get_4byte_value (notedata + 4);

      remaining -= 8;
      notedata  += 8;
      if (size > remaining)
	{
	  reason = "the property note data has an invalid size";
	  einfo (VERBOSE2, "debug: data size for note at offset %lx is %lu but remaining data is only %u",
		 (long)(notedata - (const unsigned char *) sec->data->d_buf), size, remaining);
	  goto fail;
	}

      if ((reason = handler (data, sec, type, size, notedata)) != NULL)
	goto fail;

      notedata  += ((size + (expected_quanta - 1)) & ~ (expected_quanta - 1));
      remaining -= ((size + (expected_quanta - 1)) & ~ (expected_quanta - 1));
    }

  /* Do not complain about a missing CET note yet - there may be a .note.go.buildid
     to follow, which would explain why the CET note is missing.  */
  per_file.has_property_note = true;
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
	     get_filename (data), sec->secname, (long) sec->shdr.sh_addralign);
    }

  if (startswith (sec->secname, GNU_BUILD_ATTRS_SECTION_NAME))
    {
      bool res;

      per_file.build_notes_seen = true;
      per_file.note_data.start = per_file.note_data.end = 0;
      //      per_file.seen_tools = TOOL_UNKNOWN;

      res = annocheck_walk_notes (data, sec, build_note_checker, NULL);

      per_file.component_name = NULL;
      if (per_file.note_data.start != per_file.note_data.end
	  && per_file.current_tool != TOOL_UNKNOWN)
	add_producer (data, per_file.current_tool, 0, "annobin notes", false);

      return res;
    }

  if (streq (sec->secname, ".note.gnu.property"))
    {
      return annocheck_walk_notes (data, sec, property_note_checker, NULL);
    }

  if (streq (sec->secname, ".note.go.buildid"))
    {
      /* The go buildid note does not contain version information.  But
	 it does tell us that GO was used to build the binary.

	 What we should now do is look for the "runtime.buildVersion"
	 symbol, find the relocation that sets its value, parse that
	 relocation, and then search at the resulting address in the
	 .rodata section in order to find the GO build version string.
	 But that is complex and target specific, so instead there is
	 a hack in check_code_section() to scan the .rodata section
	 directly.  */
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
      if (! startswith (str, "/usr") && ! startswith (str, "$ORIGIN"))
	return true;
      str = strchr (str, ':');
      if (str)
	str++;
    }
  return false;
}

/* Returns TRUE iff STR contains a search path that starts with $ORIGIN
   and which occurs after a path that does not start with $ORIGIN.  */

static bool
origin_path_after_non_origin_path (const char * str)
{
  bool non_origin_seen = false;

  while (str)
    {
      if (strstr (str, "$ORIGIN"))
	{
	  if (non_origin_seen)
	    return true;
	}
      else
	non_origin_seen = true;

      str = strchr (str, ':');
      if (str)
	str++;
    }
  return false;
}

/* Check the runtime search paths found in a dynamic tag.  These checks attempt
   to match the logic in /usr/lib/rpm/check-rpaths-worker, except that we do not
   complain about the presence of standard library search paths.  Return true if
   the paths were OK and false otherwise.  */

static bool
check_runtime_search_paths (annocheck_data * data, const char * path)
{
  if (path == NULL)
    fail (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RPATH/DT_RUNPATH dynamic tag is corrupt");
  else if (path[0] == 0)
    /* An empty path is useless.  */
    maybe (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RPATH/DT_RUNPATH dynamic tag exists but is empty");
  else if (not_rooted_at_usr (path))
    fail (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RPATH/DT_RUNPATH dynamic tag contains a path that does not start with /usr");
  else if (strstr (path, "..") != NULL)
    /* If a path contains .. then it may not work if the portion before it is a symlink.  */
    fail (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RPATH/DT_RUNPATH dynamic tag has a path that contains '..'");
  else if (origin_path_after_non_origin_path (path))
    /* Placing $ORIGIN paths after non-$ORIGIN paths is probably a mistake.  */
    maybe (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RPATH/DT_RUNPATH dynamic tag has $ORIGIN after a non-$ORIGIN path");
  else
    return true;
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
      einfo (VERBOSE, "%s: WARN: Dynamic section %s is empty - ignoring", get_filename (data), sec->secname);
      return true;
    }

  per_file.has_dynamic_segment = true;

  if (tests[TEST_DYNAMIC_SEGMENT].state == STATE_UNTESTED)
    pass (data, TEST_DYNAMIC_SEGMENT, SOURCE_DYNAMIC_SECTION, NULL);
  else if (tests[TEST_DYNAMIC_SEGMENT].state == STATE_PASSED)
    /* Note - we test sections before segments, so we do not
       have to worry about interesting_seg() PASSing this test.  */
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
	    fail (data, TEST_TEXTREL, SOURCE_DYNAMIC_SECTION, "the DT_TEXTREL tag was detected");
	  break;

	case DT_RPATH:
	  if (! skip_test (TEST_RUN_PATH))
	    {
	      const char * path = elf_strptr (data->elf, sec->shdr.sh_link, dyn->d_un.d_val);

	      if (check_runtime_search_paths (data, path))
		{
		  if (DT_RPATH_OK)
		    {
		      pass (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RPATH dynamic tag is present and correct");
		      inform (data, "info: the RPATH dynamic tag is deprecated.  Link with --enable-new-dtags to use RUNPATH instead");
		    }
		  else
		    {
		      skip (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the RPATH dynamic tag is deprecated but still supported for now");
		      inform (data, "info: Link with --enable-new-dtags to use RUNPATH dynamic tag instead");
		    }
		}
	    }
	  break;

	case DT_RUNPATH:
	  if (! skip_test (TEST_RUN_PATH))
	    {
	      const char * path = elf_strptr (data->elf, sec->shdr.sh_link, dyn->d_un.d_val);

	      if (check_runtime_search_paths (data, path))
		pass (data, TEST_RUN_PATH, SOURCE_DYNAMIC_SECTION, "the DT_RUNPATH dynamic tag is present and correct");
	    }
	  break;

	case DT_AARCH64_BTI_PLT:
	  aarch64_bti_plt_seen = true;
	  break;

	case DT_AARCH64_PAC_PLT:
	  aarch64_pac_plt_seen = true;
	  break;

#ifdef DF_1_PIE
	case DT_FLAGS_1:
	  per_file.has_pie_flag = (dyn->d_un.d_val & DF_1_PIE) != 0;
	  break;
#endif
	case DT_SONAME:
	  per_file.has_soname = true;
	  break;

	case DT_DEBUG:
	  per_file.has_dt_debug = true;
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
      else if (is_special_glibc_binary (data->full_filename))
	skip (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "glibc binaries do not use bind-now");
      else
	fail (data, TEST_BIND_NOW, SOURCE_DYNAMIC_SECTION, "not linked with -Wl,-z,now");
    }

  if (per_file.e_machine == EM_AARCH64)
    {
      if (is_object_file ())
	{
	  skip (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "not used in object files");
	  skip (data, TEST_NOT_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "not used in object files");
	}
      else
	{
	  uint res = aarch64_bti_plt_seen ? 1 : 0;

	  res += aarch64_pac_plt_seen ? 2 : 0;
	  switch (res)
	  {
	  case 0:
	    fail (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "BTI_PLT flag is missing from the dynamic tags");
	    pass (data, TEST_NOT_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "BTI_PLT and PAC_PLT flags not in the dynamic tags");
	    break;
	  case 1:
	    if (tests[TEST_DYNAMIC_TAGS].enabled) /* The PAC_PLT flag is Not currently used.  */
	      {
		future_fail (data, "PAC_PLT flag is missing from dynamic tags");
		pass (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "BTI_PLT flag is present in the dynamic tags");
	      }
	    fail (data, TEST_NOT_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "BTI_PLT flag is present in the dynamic tags");
	    break;
	  case 2:
	    fail (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "BTI_PLT flag is missing from the dynamic tags");
	    fail (data, TEST_NOT_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "PAC_PLT flag is present in the dynamic tags");
	    break;
	  case 3:
	    pass (data, TEST_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, NULL);
	    fail (data, TEST_NOT_DYNAMIC_TAGS, SOURCE_DYNAMIC_SECTION, "BTI (and PAC) flags are present in the dynamic tags");
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
  if (per_file.current_tool == TOOL_GO && streq (sec->secname, ".rodata"))
    {
      /* Look for a GO compiler build version.  See check_note_section()
	 for why we cannot use the .note.go.buildid section.  */
      const char * go_version = memmem (sec->data->d_buf, sec->data->d_size, "go1.", 4);

      if (go_version != NULL)
	{
	  uint version, revision;

	  go_version += 4;

	  if (sscanf (go_version, "%u.%u", & version, & revision) == 2)
	    {
	      add_producer (data, TOOL_GO, version, SOURCE_RODATA_SECTION, false);

	      /* Paranoia - check to see if there is a second, similar string.  */
	      go_version = memmem (go_version, sec->data->d_size - (go_version - (const char *) sec->data->d_buf),
				   "go1.", 4);
	      uint other_version;
	      if (go_version != NULL
		  && sscanf (go_version, "%u.%u", & other_version, & revision) == 2
		  && other_version != version)
		maybe (data, TEST_GO_REVISION, SOURCE_RODATA_SECTION, "multiple, different GO version strings found");
	    }
	  else
	    einfo (VERBOSE2, ".go1 string found in .rodata, but could not parse version info");
	}
      return true;
    }

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
		 get_filename (data), version, where);
	}
      else if ((where = strstr (tool, clang_prefix)) != NULL)
	{
	  /* FIXME: This assumes that the clang identifier looks like: "clang version 7.0.1""  */
	  version = (uint) strtod (where + strlen (clang_prefix), NULL);
	  add_producer (data, TOOL_CLANG, version, COMMENT_SECTION, true);
	  einfo (VERBOSE2, "%s: built by clang version %u (extracted from '%s' in comment section)",
		 get_filename (data), version, where);
	}
      else if (strstr (tool, lld_prefix) != NULL)
	{
	  einfo (VERBOSE2, "ignoring linker version string found in .comment section");
	}
      else if (*tool)
	{
	  einfo (VERBOSE2, "unrecognised component in .comment section: %s", tool);
	}

      /* Check for files built by tools that are not intended to produce production ready binaries.  */
      if (strstr (tool, "NOT_FOR_PRODUCTION"))
	fail (data, TEST_PRODUCTION, SOURCE_COMMENT_SECTION, "a production-ready compiler was not used to build the binary");

      tool += strlen (tool) + 1;
    }

  return true;
}

static bool
contains_suspicious_characters (const unsigned char * name)
{
  uint i;
  uint len = strlen ((const char *) name);

  /* FIXME: Test that locale is UTF-8.  */

  for (i = 0; i < len; i++)
    {
      unsigned char c = name[i];

      if (isgraph (c))
	continue;

      /* Golang allows spaces in some symbols.  */
      if (c == ' ' && (per_file.lang == LANG_GO || (per_file.seen_tools & TOOL_GO)))
	continue;

      /* Control characters are always suspect.  So are spaces and DEL  */
      if (iscntrl (c) || c == ' ' || c == 0x7f)
	return true;

      if (c < 0x7f) /* This test is probably redundant.  */
	continue;

      /* If we do not need to classify the multibyte character then stop now.  */
      if (FAIL_FOR_ANY_UNICODE)
	return true;

      if (c < 0xc0) /* Not a UTF-8 encoded byte stream character.  This is bad.  */
	return true;

      /* We have encountered a UTF-8 encoded character that uses at least 2 bytes.
	 Check to see if the next byte is available.  If it is not then something
	 bad has happened.  */
      if (++i >= len)
	return true;

      if (c < 0xe0) /* Currently there are no 2-byte encoded unicode sequences
		       that we need to worry about.  */
	return false;

      if (c >= 0xf0) /* Nor are there any dangerous 4-byte unicode sequences.  */
	{
	  i += 2;
	  if (i >= len) /* But of course if the bytes are not there then something is wrong.  */
	    return true;
	  return false;
	}

      /* We have encountered a UTF-8 encoded character that uses 3 bytes.
	 Check to see if the next byte is available.  If it is not then something
	 bad has happened.  */
      if (++i >= len)
	return true;

      /* FIXME: Add more checks for valid UTF-8 encoding.  */
      if (c != 0xe2)
	continue;

      /* Most unicode characters are fine, but some
	 have special properties make them dangerous.  */
      static const unsigned char dangerous[][3] =
	{
	  /* Q: Why bother with the first byte in these entries, since we know that it is always 0xe2 ?
	     A: Because it makes the table easy to compare with online unicode tables.  */
	  { 0xe2, 0x80, 0x8b }, /* \u200b: zero-width-space.  */
	  { 0xe2, 0x80, 0x8c }, /* \u200c: zero-width-non-joiner.  */
	  { 0xe2, 0x80, 0x8d }, /* \u200d: zero-width-joiner.  */

	  { 0xe2, 0x80, 0xaa }, /* \u202a: left-to-right embedding.  */
	  { 0xe2, 0x80, 0xab }, /* \u202b: right-to-left embedding.  */
	  { 0xe2, 0x80, 0xac }, /* \u202c: pop directional formatting.  */
	  { 0xe2, 0x80, 0xad }, /* \u202d: left-to-right override formatting.  */
	  { 0xe2, 0x80, 0xae }, /* \u202e: right-to-left override.  */

	  { 0xe2, 0x81, 0xa6 }, /* \u2066: left-to-right isolate.  */
	  { 0xe2, 0x81, 0xa7 }, /* \u2067: right-to-left isolate.  */
	  { 0xe2, 0x81, 0xa8 }, /* \u2068: first-strong isolate.  */
	  { 0xe2, 0x81, 0xa9 }  /* \u2069: popdirectional isolate.  */
	};

      /* FIXME: Should we allow direction changing at the start/end of identifiers ?  */

      uint j;
      for (j = ARRAY_SIZE (dangerous); j--;)
	/* FIXME: We could use binary slicing to make this search faster.  */
	if (name[i-1] == dangerous[j][1] && name[i] == dangerous[j][2])
	  return true;

      /* FIXME: Add test for confusable unicode characters ?  */
    }

  return false;
}

static bool
check_symbol_section (annocheck_data * data, annocheck_section * sec)
{
  if (! tests[TEST_UNICODE].enabled)
    return true;

  /* Scan the symbols looking for non-ASCII characters in their names
     that might cause problems.  Note - we do not examine the string
     tables directly as there are perfectly legitimate reasons why these
     characters might appear in strings.  But when they are used for
     identifier names, their use is ... problematic.  */
  GElf_Sym  sym;
  uint      symndx;

  for (symndx = 1; gelf_getsym (sec->data, symndx, & sym) != NULL; symndx++)
    {
      const char * symname = elf_strptr (data->elf, sec->shdr.sh_link, sym.st_name);

      if (contains_suspicious_characters ((const unsigned char *) symname))
	{
	  fail (data, TEST_UNICODE, SOURCE_SYMBOL_SECTION, "suspicious characters were found in a symbol name");
	  einfo (VERBOSE, "%s: info: symname: '%s', (%lu bytes long) in section: %s",
		 get_filename (data), symname, (unsigned long) strlen (symname), sec->secname);
	  if (!BE_VERBOSE)
	    break;
	}
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
    case SHT_SYMTAB:
    case SHT_DYNSYM:   return check_symbol_section (data, sec);
    case SHT_NOTE:     return check_note_section (data, sec);
    case SHT_STRTAB:   return check_string_section (data, sec);
    case SHT_DYNAMIC:  return check_dynamic_section (data, sec);
    case SHT_PROGBITS: return check_code_section (data, sec);
    default:           return true;
    }
}

/* Determine if the current file is a shared_library.
   The tests below have been stolen from is_shared() in the elfutils' elfclassify.c source file.  */

static bool
is_shared_lib (void)
{
  /* If it does not have a dynamic section/segment, then it cannot be a shared library.  */
  if (! per_file.has_dynamic_segment)
    return false;

#ifdef DF_1_PIE
  /* If it has a PIE flag it is an executable.  */
  if (per_file.has_pie_flag != 0)
    return false;
#endif

  /* Treat a DT_SONAME tag as a strong indicator that this is a shared
     object.  */
  if (per_file.has_soname)
    return true;

  /* This is probably a PIE program: there is no soname, but a program
     interpreter.  In theory, this file could be also a DSO with a
     soname implied by its file name that can be run as a program.
     This situation is impossible to resolve in the general case. */
  if (per_file.has_program_interpreter)
    return false;

  /* Roland McGrath mentions in
     <https://www.sourceware.org/ml/libc-alpha/2015-03/msg00605.html>,
     that “we defined a PIE as an ET_DYN with a DT_DEBUG”.  This
     matches current binutils behavior (version 2.32).  DT_DEBUG is
     added if bfd_link_executable returns true or if bfd_link_pic
     returns false, depending on the architectures.  However, DT_DEBUG
     is not documented as being specific to executables, therefore use
     it only as a low-priority discriminator.  */
  if (per_file.has_dt_debug)
    return false;

  return true;
}

static bool
interesting_seg (annocheck_data *    data,
		 annocheck_segment * seg)
{
  if (disabled)
    return false;

  if (! skip_test (TEST_RWX_SEG))
    {
      if ((seg->phdr->p_flags & (PF_X | PF_W | PF_R)) == (PF_X | PF_W | PF_R))
	{
	  /* Object files should not have segments.  */
	  assert (! is_object_file ());
	  fail (data, TEST_RWX_SEG, SOURCE_SEGMENT_HEADERS, "segment has Read, Write and eXecute flags set");
	  einfo (VERBOSE2, "RWX segment number: %d", seg->number);
	  fail (data, TEST_GNU_STACK, SOURCE_SEGMENT_HEADERS, "the GNU stack segment has execute permission");
	}
    }

  switch (seg->phdr->p_type)
    {
    case PT_INTERP:
      per_file.has_program_interpreter = true;
      break;

    case PT_GNU_RELRO:
      pass (data, TEST_GNU_RELRO, SOURCE_SEGMENT_HEADERS, NULL);
      break;

    case PT_GNU_STACK:
      if (! skip_test (TEST_GNU_STACK))
	{
	  if ((seg->phdr->p_flags & (PF_W | PF_R)) != (PF_W | PF_R))
	    fail (data, TEST_GNU_STACK, SOURCE_SEGMENT_HEADERS, "the GNU stack segment does not have both read & write permissions");
	  /* If the segment has the PF_X flag set it will have been reported as a failure above.  */
	  else if ((seg->phdr->p_flags & PF_X) == 0)
	    pass (data, TEST_GNU_STACK, SOURCE_SEGMENT_HEADERS, "stack segment exists with the correct permissions");
	}
      break;

    case PT_DYNAMIC:
      per_file.has_dynamic_segment = true;
      pass (data, TEST_DYNAMIC_SEGMENT, SOURCE_SEGMENT_HEADERS, NULL);
      /* FIXME: We do not check to see if there is a second dynamic segment.
	 Checking is complicated by the fact that there can be both a dynamic
	 segment and a dynamic section.  */
      break;

    case PT_NOTE:
      if (skip_test (TEST_PROPERTY_NOTE))
	break;
      /* We return true if we want to examine the note segments.  */
      return supports_property_notes (per_file.e_machine);

    case PT_LOAD:
      /* If we are checking the entry point instruction then we need to load
	 the segment.  We check segments rather than sections because executables
	 do not have to have sections.  */
      if (! skip_test (TEST_ENTRY)
	  && is_executable ()
	  && is_x86 ()
	  /* If GO is being used then CET is not supported.  */
	  && ((per_file.seen_tools & TOOL_GO) == 0)
	  /* Check that the entry point is inside this segment.  */
	  && seg->phdr->p_memsz > 0
	  && seg->phdr->p_vaddr <= per_file.e_entry
	  && seg->phdr->p_vaddr + seg->phdr->p_memsz > per_file.e_entry)
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

      if (seg->data == NULL
	  || entry_point + 3 >= seg->data->d_size)
	/* Fuzzing can create binaries like this.  */
	return true;

      /* We are only interested in PT_LOAD segmments if we are checking
	 the entry point instruction.  However we should not check shared
	 libraries, so test for them here.  */
      if (is_shared_lib ())
	{
	  skip (data, TEST_ENTRY, SOURCE_SEGMENT_CONTENTS, "shared libraries do not use entry points");
	  return true;
	}

      memcpy (entry_bytes, seg->data->d_buf + entry_point, sizeof entry_bytes);

      if (per_file.e_machine == EM_386)
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
		     get_filename (data), (long) per_file.e_entry,
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
		     get_filename (data), (long) per_file.e_entry,
		     entry_bytes[0], entry_bytes[1], entry_bytes[2], entry_bytes[3]);
	    }
	}

      return true;
    }

  if (seg->phdr->p_type != PT_NOTE
      || per_file.e_machine != EM_X86_64
      || skip_test (TEST_PROPERTY_NOTE))
    return true;

  /* FIXME: Only run these checks if the note section is missing ?  */

  GElf_Nhdr  note;
  size_t     name_off;
  size_t     data_off;
  size_t     offset = 0;

  if (seg->phdr->p_align != 8 && seg->phdr->p_align != 4)
    {
      fail (data, TEST_PROPERTY_NOTE, SOURCE_SEGMENT_CONTENTS, "Note segment not 4 or 8 byte aligned");
      einfo (VERBOSE2, "debug: note segment alignment: %ld", (long) seg->phdr->p_align);
    }

  offset = gelf_getnote (seg->data, offset, & note, & name_off, & data_off);
  if (offset == 0)
    {
      einfo (VERBOSE2, "Unable to retrieve note");
      /* Allow scan to continue.  */
      return true;
    }

  if (note.n_type == NT_GNU_PROPERTY_TYPE_0)
    {
      if (seg->phdr->p_align != 8)
	fail (data, TEST_PROPERTY_NOTE, SOURCE_SEGMENT_CONTENTS, "the GNU Property note segment not 8 byte aligned");
      else
	/* FIXME: We should check the contents of the note.  */
	/* FIXME: We should check so see if there is a second note.  */
	pass (data, TEST_PROPERTY_NOTE, SOURCE_SEGMENT_CONTENTS, NULL);
    }
  /* FIXME: Should we complain about other note types ?  */

  return true;
}

static bool
is_nop_byte (annocheck_data * data ATTRIBUTE_UNUSED,
	     unsigned char    byte,
	     uint             index,
	     ulong            addr_bias)
{
  switch (per_file.e_machine)
    {
    case EM_PPC64:
      /* NOP = 60000000 */
      return (((addr_bias + index) & 3) == 3) && byte == 0x60;

    case EM_AARCH64:
      /* NOP = d503201f */
      switch ((addr_bias + index) & 3)
	{
	case 0: return byte == 0x1f;
	case 1: return byte == 0x20;
	case 2: return byte == 0x03;
	case 3: return byte == 0xd5;
	}

    case EM_S390:
      /* NOP = 47000000 */
      return (((addr_bias + index) & 3) == 3) && byte == 0x47;

    default:
      /* FIXME: Add support for other architectures.  */
      /* FIXME: Add support for alternative endianness.  */
      return false;
    }
}

/* Returns true if GAP is one that can be ignored.  */

static bool
ignore_gap (annocheck_data * data, note_range * gap)
{
  Elf_Scn * addr1_scn = NULL;
  Elf_Scn * addr2_scn = NULL;
  Elf_Scn * prev_scn = NULL;
  Elf_Scn * scn = NULL;
  ulong     scn_end = 0;
  ulong     scn_name = 0;
  ulong     addr1_bias = 0;

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

  einfo (VERBOSE2, "Consider gap %#lx..%#lx", gap->start, gap->end);

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

  gap->start = align (gap->start, per_file.text_section_alignment);

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
	  ulong sec_end = shdr->sh_addr + shdr->sh_size;

	  /* We are only interested in code sections.  */
	  if (shdr->sh_type != SHT_PROGBITS
	      || (shdr->sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) != (SHF_ALLOC | SHF_EXECINSTR))
	    continue;

	  if ((shdr->sh_addr <= gap->start) && (gap->start < sec_end))
	    {
	      /* Record any section as a first match.  */
	      if (addr1_scn == NULL)
		{
		  addr1_scn = scn;
		  addr1_bias = gap->start - shdr->sh_addr;
		  scn_name = shdr->sh_name;
		  scn_end = sec_end;
		}
	      else
		{
		  /* FIXME: Which section should we select ?  */
		  einfo (VERBOSE2, "multiple code sections (%x+%x vs %x+%x) contain gap start",
			 shdr->sh_addr, shdr->sh_size,
			 elf32_getshdr (addr1_scn)->sh_addr,
			 elf32_getshdr (addr1_scn)->sh_size
			 );
		}
	    }

	  if ((shdr->sh_addr < gap->end) && (gap->end < sec_end))
	    {
	      /* Record any section as a first match.  */
	      if (addr2_scn == NULL)
		addr2_scn = scn;
	      else
		{
		  /* FIXME: Which section should we select ?  */
		  const Elf64_Shdr * addr1 = elf64_getshdr (addr1_scn);

 		  einfo (VERBOSE2, "multiple code sections (%lx+%lx vs %lx+%lx) contain gap end",
 			 (unsigned long) shdr->sh_addr,
 			 (unsigned long) shdr->sh_size,
			 (unsigned long) (addr1 ? addr1->sh_addr : 0),
			 (unsigned long) (addr1 ? addr1->sh_size : 0));
		}
	    }
	  else if (shdr->sh_addr == gap->end)
	    {
	      /* This gap ends at the start of the current section.
		 So it probably matches the previous section.  */
	      if (addr2_scn == NULL
		  && prev_scn != NULL
		  && prev_scn == addr1_scn)
		{
		  addr2_scn = prev_scn;
		}
	    }

	  prev_scn = scn;
	}
    }
  else
    {
      while ((scn = elf_nextscn (data->elf, scn)) != NULL)
	{
	  Elf64_Shdr * shdr = elf64_getshdr (scn);
	  ulong sec_end = shdr->sh_addr + shdr->sh_size;

	  /* We are only interested in code sections.  */
	  if (shdr->sh_type != SHT_PROGBITS
	      || (shdr->sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) != (SHF_ALLOC | SHF_EXECINSTR))
	    continue;

	  if ((shdr->sh_addr <= gap->start) && (gap->start < sec_end))
	    {
	      /* Record any section as a first match.  */
	      if (addr1_scn == NULL)
		{
		  addr1_scn = scn;
		  addr1_bias = gap->start - shdr->sh_addr;
		  scn_name = shdr->sh_name;
		  scn_end = sec_end;
		}
	      else
		{
		  /* FIXME: Which section should we select ?  */
		  einfo (VERBOSE2, "multiple code sections (%lx+%lx vs %lx+%lx) contain gap start",
			 (unsigned long) shdr->sh_addr,
			 (unsigned long) shdr->sh_size,
			 (unsigned long) elf64_getshdr (addr1_scn)->sh_addr,
			 (unsigned long) elf64_getshdr (addr1_scn)->sh_size
			 );
		}
	    }

	  if ((shdr->sh_addr < gap->end) && (gap->end < sec_end))
	    {
	      /* Record any section as a first match.  */
	      if (addr2_scn == NULL)
		addr2_scn = scn;
	      else
		{
		  /* FIXME: Which section should we select ?  */
		  einfo (VERBOSE2, "multiple code sections (%lx+%lx vs %lx+%lx) contain gap end",
			 (unsigned long) shdr->sh_addr,
			 (unsigned long) shdr->sh_size,
			 (unsigned long) elf64_getshdr (addr1_scn)->sh_addr,
			 (unsigned long) elf64_getshdr (addr1_scn)->sh_size);
		}
	    }
	  else if (shdr->sh_addr == gap->end)
	    {
	      /* This gap ends at the start of the current section.
		 So it probably matches the previous section.  */
	      if (addr2_scn == NULL
		  && prev_scn != NULL
		  && prev_scn == addr1_scn)
		{
		  addr2_scn = prev_scn;
		}
	    }

	  prev_scn = scn;
	}
    }

  /* If the gap is not inside one or more sections, then something funny has gone on...  */
  if (addr1_scn == NULL || addr2_scn == NULL)
    {
      einfo (VERBOSE2, "gap is strange: it does not start and/or end in a section - ignoring");
      return true;
    }

  /* If the gap starts in one section, but ends in a different section then we ignore it.  */
  if (addr1_scn != addr2_scn)
    {
      einfo (VERBOSE2, "gap ignored: crosses section boundary");
      return true;
    }

  size_t shstrndx;

  if (elf_getshdrstrndx (data->elf, & shstrndx) >= 0)
    {
      const char * secname;

      secname = elf_strptr (data->elf, shstrndx, scn_name);
      if (secname != NULL)
	{
	  if (streq (secname, ".plt"))
	    {
	      einfo (VERBOSE2, "Ignoring gaps in the .plt section");
	      return true;
	    }
	  if (streq (secname, ".got"))
	    {
	      einfo (VERBOSE2, "Ignoring gaps in the .got section");
	      return true;
	    }
	}
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
	      einfo (VERBOSE2, "Ignoring gap at end of ppc64 .text section - it contains PLT stubs");
	      return true;
	    }
	  else
	    {
	      einfo (VERBOSE2, "Potential PLT stub gap contains the symbol '%s', so the gap is not ignored", sym);
	      return false;
	    }
	}
      else
	{
	  /* Without symbol information we cannot be sure, but it is a reasonable supposition.  */
	  einfo (VERBOSE2, "Ignoring gap at end of ppc64 .text section - it will contain PLT stubs");
	  return true;
	}
    }

  /* Scan the contents of the gap.  If it is all zeroes or NOP instructions, then it can be ignored.  */
  Elf_Data * sec_data;
  sec_data = elf_getdata (addr1_scn, NULL);
  /* Paranoia checks.  */
  if (sec_data == NULL
      || sec_data->d_off != 0
      || sec_data->d_type != ELF_T_BYTE
      || gap->start < addr1_bias /* This should never happen.  */
      || (gap->end - addr1_bias) >= sec_data->d_size) /* Nor should this.  */
    {
      einfo (VERBOSE2, "could not check gap for NOPs!");
      return false;
    }

  unsigned char * sec_bytes = ((unsigned char *) sec_data->d_buf) + addr1_bias;
  uint i;
  for (i = gap->end - gap->start; i--;)
    if (sec_bytes[i] != 0 && ! is_nop_byte (data, sec_bytes[i], i, addr1_bias))
      break;

  if (i == (uint) -1)
    {
      einfo (VERBOSE2, "gap ignored - it contains padding and/or NOP instructions");
      return true;
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
skip_gap_sym (annocheck_data * data, const char * sym)
{
  if (sym == NULL)
    return false;

  /* G++ will generate virtual and non-virtual thunk functions all on its own,
     without telling the annobin plugin about them.  Detect them here and do
     not complain about the gap in the coverage.  */
  if (startswith (sym, "_ZThn") || startswith (sym, "_ZTv0"))
    return true;

  /* The GO infrastructure is not annotated.  */
  if (startswith (sym, "internal/cpu.Initialize"))
    return true;

  /* If the symbol is for a function/file that we know has special
     reasons for not being proplerly annotated then we skip it.  */
  const char * saved_sym = per_file.component_name;
  per_file.component_name = sym;
  if (skip_test_for_current_func (data, TEST_MAX))
    {
      per_file.component_name = saved_sym;
      return true;
    }
  per_file.component_name = saved_sym;

  if (per_file.e_machine == EM_X86_64)
    {
      /* See BZ 2031133 for example of this happening with RHEL-7 builds.  */
      if (startswith (sym, "deregister_tm_clones"))
	return true;

      /* See BZ 2040688: RHEL-6 binaries can have this symvol in their glibc code regions.  */
      if (startswith (sym, "call_gmon_start"))
	return true;
    }
  else if (per_file.e_machine == EM_AARCH64)
    {
      if (startswith (sym, "_start"))
	return true;
      if (streq (sym, "_dl_start_user"))
	return true;
    }
  else if (per_file.e_machine == EM_386)
    {
      if (startswith (sym, "__x86.get_pc_thunk")
	  || startswith (sym, "_x86_indirect_thunk_"))
	return true;
    }
  else if (per_file.e_machine == EM_PPC64)
    {
      if (startswith (sym, "_savegpr")
	  || startswith (sym, "_restgpr")
	  || startswith (sym, "_savefpr")
	  || startswith (sym, "_restfpr")
	  || startswith (sym, "_savevr")
	  || startswith (sym, "_restvr"))
	return true;

      /* The linker can also generate long call stubs.  They have the form:
         NNNNNNNN.<stub_name>.<func_name>.  */
      const size_t len = strlen (sym);
      if (   (len > 8 + 10 && startswith (sym + 8, ".plt_call."))
	  || (len > 8 + 12 && startswith (sym + 8, ".plt_branch."))
	  || (len > 8 + 13 && startswith (sym + 8, ".long_branch.")))
	return true;

      /* The gdb server program contains special assembler stubs that
	 are unannotated.  See BZ 1630564 for more details.  */
      if (startswith (sym, "start_bcax_"))
	return true;

      /* Not sure where this one comes from, but it has been reported in BZ 2043047.  */
      if (streq (sym, "log_stderr"))
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
  const char * first_sym = NULL;

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
	  if (sym != NULL && skip_gap_sym (data, sym))
	    {
	      einfo (VERBOSE2, "gap ignored - special symbol: %s", sym);

	      /* FIXME: Really we should advance the gap start to the end of the address
		 range covered by the symbol and then check for gaps again.  But this will
		 probably causes us more problems than we want to handle right now.  */
	      continue;
	    }

	  if (sym != NULL)
	    first_sym = strdup (sym);

	  /* If the start of the range was not aligned to a function boundary
	     then try again, this time with an aligned start symbol.
	     FIXME: 16 is suitable for x86_64, but not necessarily other architectures.  */
	  if (gap.start != align (gap.start, 16))
	    {
	      const char * sym2;

	      sym2 = annocheck_find_symbol_for_address_range (data, NULL, align (gap.start, 16), gap.end, false);
	      if (sym2 != NULL
		  && strstr (sym2, ".end") == NULL
		  && (first_sym == NULL || strcmp (sym2, first_sym) != 0))
		{
		  if (skip_gap_sym (data, sym2))
		    {
		      einfo (VERBOSE2, "gap ignored - special symbol: %s", sym2);
		      /* See comment above.  */
		      free ((char *) first_sym);
		      first_sym = NULL;
		      continue;
		    }

		  if (first_sym == NULL)
		    {
		      gap.start = align (gap.start, 16);
		      first_sym = strdup (sym2);
		    }
		}
	    }

	  /* Finally, give it one more go, looking for a symbol half way through the gap.  */
	  if (gap.end - gap.start > 32)
	    {
	      const char * sym2;
	      ulong start = align (gap.start + ((gap.end - gap.start) / 2), 32);

	      sym2 = annocheck_find_symbol_for_address_range (data, NULL, start, start + 32, false);

	      if (sym2 != NULL && strstr (sym2, ".end") == NULL)
		{
		  if (skip_gap_sym (data, sym2))
		    {
		      einfo (VERBOSE2, "gap ignored - special symbol: %s", sym2);
		      /* See comment above.  */
		      free ((char *) first_sym);
		      first_sym = NULL;
		      continue;
		    }

		  if (first_sym == NULL)
		    first_sym = strdup (sym2);
		}
	    }

	  gap_found = true;
	  if (! BE_VERBOSE)
	    {
	      free ((char *) first_sym);
	      break;
	    }

	  if (first_sym)
	    {
	      if (first_sym[0] == '_' && first_sym[1] == 'Z')
		{
		  const char * cpsym = NULL;

		  cpsym = cplus_demangle (sym, DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE);
		  if (cpsym != NULL)
		    {
		      free ((char *) first_sym);
		      first_sym = cpsym;
		    }
		}

	      einfo (VERBOSE, "%s: gap:  (%#lx..%#lx probable component: %s) in annobin notes",
		     get_filename (data), gap.start, gap.end, first_sym);

	      free ((char *) first_sym);
	      first_sym = NULL;
	    }
	  else
	    einfo (VERBOSE, "%s: gap:  (%#lx..%#lx) in annobin notes",
		   get_filename (data), gap.start, gap.end);
	}
    }

  if (gap_found)
    {
      fail (data, TEST_NOTES, SOURCE_ANNOBIN_NOTES, "gaps were detected in the annobin coverage");
      return;
    }

  /* Now check to see that the notes covered the whole of the .text section.  */
  /* FIXME: We should actually do this for every executable section.  */
  /* FIXME: we know that the PPC64 and S390 will put linker generated code at the start and/or
     end of the .text section, so we skip this next test.  Ideally we would have a way to detect
     linker generated code, such as detecting known stub function names...  */
  if (per_file.e_machine == EM_PPC64 || per_file.e_machine == EM_S390)
    {
      pass (data, TEST_NOTES, SOURCE_ANNOBIN_NOTES, "no gaps found");
      return;
    }

  /* Scan forward through the ranges array looking for overlaps with the start of the .text section.  */
  if (per_file.text_section_range.end != 0)
    {
      for (i = 0; i < next_free_range; i++)
	{
	  if (ranges[i].start <= per_file.text_section_range.start
	      && ranges [i].end > per_file.text_section_range.start)
	    /* We have found a note range that occludes the start of the text section.
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

  if (per_file.text_section_range.end > per_file.text_section_range.start)
    {
      const char * sym = annocheck_find_symbol_for_address_range (data, NULL, per_file.text_section_range.start,
								  per_file.text_section_range.end, false);

      if (sym != NULL && skip_gap_sym (data, sym))
	einfo (VERBOSE2, "gap ignored - special symbol: %s", sym);
      else
	{
	  ulong gap = per_file.text_section_range.end - per_file.text_section_range.start;

	  /* FIXME _ SCAN FOR NOPS!  */
	  /* The AArch64 target can insert up to 0x3c bytes of padding...
	     cf BZ 1995224.  */
	  if (gap > 0x3c || per_file.e_machine != EM_AARCH64)
	    {
	      maybe (data, TEST_NOTES, SOURCE_ANNOBIN_NOTES, "not all of the .text section is covered by notes");
	      if (sym != NULL)
		einfo (VERBOSE, "%s: info: address range not covered: %lx..%lx (probable component: %s)",
		       get_filename (data), per_file.text_section_range.start, per_file.text_section_range.end, sym);
	      else
		einfo (VERBOSE, "%s: info: address range not covered: %lx..%lx",
		       get_filename (data), per_file.text_section_range.start, per_file.text_section_range.end);		
	      return;
	    }
	  else
	    einfo (VERBOSE2, "small gap of %lx bytes ignored", gap);
	}
    }

  pass (data, TEST_NOTES, SOURCE_ANNOBIN_NOTES, "no gaps found");
}

static bool
C_compiler_seen (void)
{
  return is_C_compiler (per_file.seen_tools_with_code)
    /* Object files do not record a note range, so seen_tools_with_code will not have been updated.  */
    || (is_object_file () && is_C_compiler (per_file.seen_tools));
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
      einfo (VERBOSE2, "%s: info: running subchecker on %s", get_filename (data), data->dwarf_filename);
      annocheck_process_extra_file (& hardened_notechecker, data->dwarf_filename, get_filename (data), data->dwarf_fd);
    }

  if (! per_file.build_notes_seen
      && per_file.e_machine != EM_ARM
      && is_C_compiler (per_file.seen_tools))
    fail (data, TEST_NOTES, SOURCE_ANNOBIN_NOTES, "annobin notes were not found");

  if (! ignore_gaps)
    {
      if (is_object_file ())
	einfo (VERBOSE, "%s: skip: Not checking for gaps (object file)", get_filename (data));
      else if (! is_C_compiler (per_file.seen_tools) && ! includes_assembler (per_file.seen_tools))
	einfo (VERBOSE, "%s: skip: Not checking for gaps (binary created by a tool without an annobin plugin)",
	       get_filename (data));
      else if (per_file.seen_tools & TOOL_GO)
	einfo (VERBOSE, "%s: skip: Not checking for gaps (binary at least created by GO)",
	       get_filename (data));
      else if (per_file.e_machine == EM_ARM)
	/* The annobin plugin for gcc is not used when building ARM binaries
	   because there is an outstanding BZ agains annobin and glibc:
	   https://bugzilla.redhat.com/show_bug.cgi?id=1951492  */
	einfo (VERBOSE, "%s: skip: Not checking for gaps (ARM binary)", get_filename (data));
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
	      if (is_kernel_module (data))
		skip (data, i, SOURCE_FINAL_SCAN, "kernel modules do not need a GNU type stack section");
	      else if (is_grub_module (data))
		skip (data, i, SOURCE_FINAL_SCAN, "grub modules do not need a GNU type stack section");		
#ifdef EM_BPF
	      else if (per_file.e_machine == EM_BPF)
		skip (data, i, SOURCE_FINAL_SCAN, "BPF binaries are special");
#endif
	      else if (is_object_file ())
		{
		  fail (data, i, SOURCE_FINAL_SCAN, "no .note.GNU-stack section found");
		  if (includes_assembler (per_file.seen_tools))
		    info (data, i, SOURCE_FINAL_SCAN, "possibly need to add '.section .note.GNU-stack,\"\",%progbits' to the assembler sources");
		}
	      else
		maybe (data, i, SOURCE_FINAL_SCAN, "no GNU-stack found");
	      break;

	    case TEST_LTO:
	      if (per_file.seen_tools & TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "at least part of the binary is compield GO");
	      else if (! C_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "not compiled C/C++ code");
	      else if (per_file.e_machine == EM_ARM)
		skip (data, i, SOURCE_FINAL_SCAN, "ARM binaries are built without annobin annotation");
	      else if (is_special_glibc_binary (data->full_filename))
		skip (data, i, SOURCE_FINAL_SCAN, "glibc binaries not compiled with LTO");
	      else
		maybe (data, i, SOURCE_FINAL_SCAN, "no indication that LTO was used");
	      break;

	    case TEST_PIE:
	      if (per_file.e_type == ET_EXEC)
		{
		  if (per_file.seen_tools & TOOL_GO)
		    skip (data, TEST_PIE, SOURCE_ELF_HEADER, "GO binaries are safe without PIE");
		  else
		    fail (data, TEST_PIE, SOURCE_ELF_HEADER, "not built with '-Wl,-pie'");
		}
	      break;
	      
	    case TEST_INSTRUMENTATION:
	    case TEST_PRODUCTION:
	    case TEST_NOTES:
	    case TEST_ENTRY:
	    case TEST_SHORT_ENUMS:
	    case TEST_DYNAMIC_SEGMENT:
	    case TEST_RUN_PATH:
	    case TEST_RWX_SEG:
	    case TEST_TEXTREL:
	    case TEST_THREADS:
	    case TEST_WRITABLE_GOT:
	    case TEST_UNICODE:
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

	    case TEST_NOT_DYNAMIC_TAGS:
	    case TEST_DYNAMIC_TAGS:
	      if (per_file.e_machine != EM_AARCH64)
		skip (data, i, SOURCE_FINAL_SCAN, "AArch64 specific");
	      else if (is_object_file ())
		skip (data, i, SOURCE_FINAL_SCAN, "not used in object files");
	      else
		{
		  fail (data, TEST_DYNAMIC_TAGS, SOURCE_FINAL_SCAN, "no dynamic tags found");
		  pass (data, TEST_NOT_DYNAMIC_TAGS, SOURCE_FINAL_SCAN, "no dynamic tags found");
		}
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
	      if (per_file.lto_used)
		skip (data, i, SOURCE_FINAL_SCAN, "compiling in LTO mode hides preprocessor and warning options");
	      else if (is_kernel_module (data))
		skip (data, i, SOURCE_FINAL_SCAN, "kernel modules are not compiled with this feature");
	      else if (per_file.seen_tools & TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "GO compilation does not use the C preprocessor");
#ifdef EM_BPF
	      else if (per_file.e_machine == EM_BPF)
		skip (data, i, SOURCE_FINAL_SCAN, "BPF binaries are special");
#endif
	      else if (per_file.e_machine == EM_ARM)
		/* The macros file from redhat-rpm-config explicitly disables the annobin plugin for ARM32
		   because of the problems reported in https://bugzilla.redhat.com/show_bug.cgi?id=1951492
		   So until that issue is resolved (if it ever is), we can expect missing notes for ARM32.  */
		skip (data, i, SOURCE_FINAL_SCAN, "ARM32 code is usually compiled without annobin plugin support");
	      else if (is_special_glibc_binary (data->full_filename))
		skip (data, i, SOURCE_FINAL_SCAN, "glibc binaries are not compiled with this feature");		
	      else if (C_compiler_seen ())
		fail (data, i, SOURCE_FINAL_SCAN, "no indication that the necessary option was used (and a C compiler was detected)");
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "no C/C++ compiled code found");
	      break;

	    case TEST_PIC:
	      if (per_file.seen_tools & TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "GO binaries are safe without PIC");
	      else if (! C_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "not C/C++ compiled code");
	      else if (per_file.e_machine == EM_ARM)
		skip (data, i, SOURCE_FINAL_SCAN, "ARM binaries are built without annobin annotation");
	      else
		maybe (data, i, SOURCE_FINAL_SCAN, "no valid notes found regarding this test");
	      break;

	    case TEST_STACK_PROT:
	      if (per_file.current_tool == TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "GO is stack safe");
	      else if (per_file.seen_tools == TOOL_GAS
		       || (per_file.gcc_from_comment && per_file.seen_tools == (TOOL_GAS | TOOL_GCC)))
		skip (data, i, SOURCE_FINAL_SCAN, "no compiled code found");
	      else if (per_file.lto_used)
		skip (data, i, SOURCE_FINAL_SCAN, "compiling in LTO mode hides the -fstack-protector-strong option");
	      else if (! C_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "not compiled C/C++ code");
	      else if (is_special_glibc_binary (data->full_filename))
		skip (data, i, SOURCE_FINAL_SCAN, "glibc binaries do not use stack protection");
	      else if (per_file.e_machine == EM_ARM)
		skip (data, i, SOURCE_FINAL_SCAN, "ARM binaries are built without annobin annotation");
	      else
		maybe (data, i, SOURCE_FINAL_SCAN, "no notes found regarding this feature");
	      break;

	    case TEST_OPTIMIZATION:
	      if (per_file.seen_tools & TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "GO optimized by default");
	      else if (per_file.e_machine == EM_ARM)
		skip (data, i, SOURCE_FINAL_SCAN, "ARM binaries are built without annobin annotation");
	      else if (! C_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "not C/C++ compiled code");
	      else
		maybe (data, i, SOURCE_FINAL_SCAN, "no valid notes found regarding this test");
	      break;

	    case TEST_STACK_CLASH:
	      if (per_file.e_machine == EM_ARM)
		skip (data, i, SOURCE_FINAL_SCAN, "not supported on ARM architectures");
	      else if (per_file.seen_tools == TOOL_GAS
		       || (per_file.gcc_from_comment && per_file.seen_tools == (TOOL_GAS | TOOL_GCC)))
		skip (data, i, SOURCE_FINAL_SCAN, "no compiled code found");
	      else if (per_file.current_tool == TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "GO is stack safe");
	      else if (! C_compiler_seen ())
		skip (data, i, SOURCE_FINAL_SCAN, "no C/C++ compiled code found");
	      else if (is_kernel_module (data))
		skip (data, i, SOURCE_FINAL_SCAN, "kernel modules do not support stack clash protection");
	      else if (per_file.seen_tools & TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "GO does not support stack clash protection");
	      else if (per_file.lto_used)
		skip (data, i, SOURCE_FINAL_SCAN, "compiling in LTO mode hides the -fstack-clash-protection option");
#ifdef EM_BPF
	      else if (per_file.e_machine == EM_BPF)
		skip (data, i, SOURCE_FINAL_SCAN, "BPF binaries are special");
#endif
	      else
		maybe (data, i, SOURCE_FINAL_SCAN, "no notes found regarding this test");
	    break;

	    case TEST_PROPERTY_NOTE:
	      if (! supports_property_notes (per_file.e_machine))
		skip (data, i, SOURCE_FINAL_SCAN, "property notes not used");
	      else if (is_object_file ())
		skip (data, i, SOURCE_FINAL_SCAN, "property notes not needed in object files");
	      else if (per_file.seen_tools & TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "property notes not needed for GO binaries");
	      else if (per_file.seen_tools & TOOL_RUST)
		skip (data, i, SOURCE_FINAL_SCAN, "property notes are not currently supported by Rust binaries");
	      else if (per_file.e_machine == EM_AARCH64)
		{
		  if (tests[TEST_BRANCH_PROTECTION].enabled)
		    {
		      if (per_file.has_property_note)
			pass (data, i, SOURCE_FINAL_SCAN, "properly formatted .note.gnu.property section found");
		      else
			fail (data, i, SOURCE_FINAL_SCAN, "properly formatted .note.gnu.property not found (it is needed for branch protection support)");
		    }
		  else
		    pass (data, i, SOURCE_FINAL_SCAN, "the AArch64 property note is only useful if branch protection is being checked");
		}
	      else if (is_x86 ())
		{
		  if (per_file.has_cf_protection)
		    pass (data, i, SOURCE_FINAL_SCAN, "CET enabled property note found");
		  else if (per_file.has_property_note)
		    {
		      if (tests[TEST_CF_PROTECTION].enabled)
			fail (data, i, SOURCE_FINAL_SCAN, "a property note was found but it shows that cf-protection is not enabled");
		      else
			pass (data, i, SOURCE_FINAL_SCAN, "a property note was found.  (Not CET enabled, but this is not being checked)");
		    }
		}
	      else if (per_file.has_property_note)
		pass (data, i, SOURCE_FINAL_SCAN, "propertu note found");
	      else
		fail (data, i, SOURCE_FINAL_SCAN, "no .note.gnu.property section found");
	      break;

	    case TEST_CF_PROTECTION:
	      if (! is_x86 ())
		skip (data, i, SOURCE_FINAL_SCAN, "not an x86 binary");
	      else if (! is_executable ())
		skip (data, i, SOURCE_FINAL_SCAN, "not an x86 executable");
	      else if (per_file.seen_tools & TOOL_GO)
		skip (data, i, SOURCE_FINAL_SCAN, "control flow protection is not needed for GO binaries");
	      else if (per_file.seen_tools & TOOL_RUST)
		skip (data, i, SOURCE_FINAL_SCAN, "control flow protection is not currently supported by Rust binaries");
	      else if (! per_file.has_cf_protection)
		fail (data, i, SOURCE_FINAL_SCAN, ".note.gnu.property section did not contain the necessary flags");
	      else if (tests[TEST_PROPERTY_NOTE].enabled)
		{
		  if (tests[TEST_PROPERTY_NOTE].state == STATE_UNTESTED)
		    fail (data, i, SOURCE_FINAL_SCAN, "no .note.gnu.property section = no control flow information");
		  else if (tests[TEST_PROPERTY_NOTE].state != STATE_PASSED)
		    fail (data, i, SOURCE_FINAL_SCAN, ".note.gnu.property section did not contain the expected notes");
		  else
		    pass (data, i, SOURCE_FINAL_SCAN, "control flow information is correct");
		}
	      else
		fail (data, i, SOURCE_FINAL_SCAN, "control flow protection is not enabled");
	      break;

	    case TEST_STACK_REALIGN:
	      if (per_file.e_machine != EM_386)
		{
		  if (per_file.e_machine == EM_X86_64)
		    skip (data, i, SOURCE_FINAL_SCAN, "not a 32-bit i686 executable");
		  else
		    skip (data, i, SOURCE_FINAL_SCAN, "not an x86 executable");
		}
	      else if (! includes_gcc (per_file.seen_tools_with_code)
		       && ! includes_gimple (per_file.seen_tools_with_code))
		skip (data, i, SOURCE_FINAL_SCAN, "no GCC compiled code found");
	      else if (per_file.lto_used)
		skip (data, i, SOURCE_FINAL_SCAN, "compiling in LTO mode hides the -mstackrealign option");
	      else
		maybe (data, i, SOURCE_FINAL_SCAN, "no indication that the -mstackrealign option was used");
	      break;

	    case TEST_NOT_BRANCH_PROTECTION:
	    case TEST_BRANCH_PROTECTION:
	      if (per_file.e_machine != EM_AARCH64)
		skip (data, i, SOURCE_FINAL_SCAN, "not an AArch64 binary");
	      else if (! includes_gcc (per_file.seen_tools_with_code)
		       && ! includes_gimple (per_file.seen_tools_with_code))
		skip (data, i, SOURCE_FINAL_SCAN, "not built by GCC");
	      else
		{
		  if (i == TEST_BRANCH_PROTECTION)
		    {
		      if (per_file.tool_version < 9 && per_file.tool_version > 3)
			skip (data, i, SOURCE_FINAL_SCAN, "needs gcc 9+");
		      else
			fail (data, i, SOURCE_FINAL_SCAN, "the -mbranch-protection option was not used");
		    }
		  else
		    pass (data, i, SOURCE_FINAL_SCAN, "the -mbranch-protection option was not used");
		}
	      break;

	    case TEST_GO_REVISION:
	      if (per_file.seen_tools & TOOL_GO)
		fail (data, i, SOURCE_FINAL_SCAN, "no Go compiler revision information found");
	      else
		skip (data, i, SOURCE_FINAL_SCAN, "no GO compiled code found");
	      break;

	    case TEST_ONLY_GO:
	      if (! is_x86 ())
		skip (data, i, SOURCE_FINAL_SCAN, "not compiled for x86");
	      else if (per_file.seen_tools == TOOL_GO)
		pass (data, i, SOURCE_FINAL_SCAN, "only GO compiled code found");
	      else if (per_file.seen_tools & TOOL_GO)
		{
#if 0
		  fail (data, i, SOURCE_FINAL_SCAN, "mixed GO and another language found");
#else
		  skip (data, i, SOURCE_FINAL_SCAN, "mixed GO and another language found, but ignored for now");
#endif
		}
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
      einfo (INFO, "%s: Overall: FAIL", get_filename (data));
      return false;
    }

  if (per_file.num_maybes > 0)
    {
      einfo (INFO, "%s: Overall: FAIL (due to MAYB results)", get_filename (data));
      return false; /* FIXME: Add an option to ignore MAYBE results ? */
    }

  if (BE_VERBOSE)
    einfo (INFO, "%s: Overall: PASS", get_filename (data));
  else
    einfo (INFO, "%s: PASS", get_filename (data));

  return true;
}

#define MAX_DISABLED 10

static const struct profiles
{
  const char *      name;
  enum  test_index  disabled_tests[MAX_DISABLED];
  enum  test_index  enabled_tests[MAX_DISABLED];
}
  profiles [PROFILE_MAX] =
{
  [ PROFILE_EL7 ] = { "el7",
		      { TEST_BRANCH_PROTECTION, TEST_DYNAMIC_TAGS, TEST_PIE, TEST_BIND_NOW, TEST_FORTIFY, TEST_STACK_CLASH, TEST_LTO, TEST_ENTRY, TEST_PROPERTY_NOTE, TEST_CF_PROTECTION },
		      { TEST_NOT_BRANCH_PROTECTION, TEST_NOT_DYNAMIC_TAGS } },
  [ PROFILE_EL8 ] = { "el8",
		      { TEST_BRANCH_PROTECTION, TEST_DYNAMIC_TAGS, TEST_LTO },
		      { TEST_NOT_BRANCH_PROTECTION, TEST_NOT_DYNAMIC_TAGS } },
  [ PROFILE_EL9 ] = { "el9",
		      { TEST_BRANCH_PROTECTION, TEST_DYNAMIC_TAGS },
		      { TEST_NOT_BRANCH_PROTECTION, TEST_NOT_DYNAMIC_TAGS } },
  [ PROFILE_RAWHIDE ] = { "rawhide",
			  { TEST_NOT_BRANCH_PROTECTION, TEST_NOT_DYNAMIC_TAGS },
			  { TEST_BRANCH_PROTECTION, TEST_DYNAMIC_TAGS } }
};

static void
set_profile (enum profile num)
{
  uint j;

  current_profile = num;

  for (j = 0; j < MAX_DISABLED; j++)
    {
      enum test_index index = profiles[num].disabled_tests[j];

      if (index == TEST_NOTES)
	break;
      tests[index].enabled = false;
    }

  for (j = 0; j < MAX_DISABLED; j++)
    {
      enum test_index index = profiles[num].enabled_tests[j];

      if (index == TEST_NOTES)
	break;
      tests[index].enabled = true;
    }

  if (num == PROFILE_RAWHIDE)
    {
      dt_rpath_is_ok.option_value = false;
      dt_rpath_is_ok.option_set = true;
    }
  else if (num != PROFILE_NONE)
    {
      dt_rpath_is_ok.option_value = true;
      dt_rpath_is_ok.option_set = true;
    }
}

static void
version (void)
{
  einfo (INFO, "Version 1.5");
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
  einfo (INFO, "  To enable a disabled test use:");
  einfo (INFO, "    --test-<name>             Enables the named test");

  einfo (INFO, "  The unicode test by default only checks for suspicious multibyte characters");
  einfo (INFO, "  but this can be extended to trigger for any multibyte character with:");
  einfo (INFO, "    --test-unicode-all        Fail if any multibyte character is detected");
  einfo (INFO, "    --test-unicode-suspicious Fail if a suspicious multibyte character is detected");

  einfo (INFO, "  Some tests report potential future problems that are not enforced at the moment");
  einfo (INFO, "    --skip-future             Disables these future fail tests (default)");
  einfo (INFO, "    --test-future             Enable the future fail tests");

  einfo (INFO, "  To enable/disable tests for a specific environment use:");
  einfo (INFO, "    --profile=[default|el7|el8|el9|rawhide]");
  einfo (INFO, "                              Ensure that only tests suitable for a specific OS are run");

  einfo (INFO, "  The tool will also report missing annobin data unless:");
  einfo (INFO, "    --ignore-gaps             Ignore missing annobin data");
  einfo (INFO, "    --report-gaps             Report missing annobin data (default)");

  einfo (INFO, "  The tool is enabled by default.  This can be changed by:");
  einfo (INFO, "    --disable-hardened        Disables the hardening checker");
  einfo (INFO, "    --enable-hardened         Reenables the hardening checker");

  einfo (INFO, "  The tool will generate messages based upon the verbosity level but the format is not fixed");
  einfo (INFO, "  In order to have a consistent output enable this option:");
  einfo (INFO, "    --fixed-format-messages   Display messages in a fixed format");

  einfo (INFO, "  By default when not opeating in verbose more only the filename of input files will be displayed in messages");
  einfo (INFO, "  This can be changed with:");
  einfo (INFO, "    --full-filenames          Display the full path of input files");
  einfo (INFO, "    --base-filenames          Display only the filename of input files");

  einfo (INFO, "  When the output is directed to a terminal colouring will be used to highlight significant messages");
  einfo (INFO, "  This can be controlled by:");
  einfo (INFO, "    --disable-colour          Disables coloured messages");
  einfo (INFO, "    --disable-color           Disables colored messages");
  einfo (INFO, "    --enable-colour           Enables coloured messages");
  einfo (INFO, "    --enable-color            Enables colored messages");

  einfo (INFO, "  Annobin's online documentation includes an extended description of the tests");
  einfo (INFO, "  run here.  By default when a FAIL or MAYB result is displayed a URL to the");
  einfo (INFO, "  relevant online description is also included (unless fixed-format mode is enabled)");
  einfo (INFO, "  This behaiour can be disabled by:");
  einfo (INFO, "    --no-urls                 Do not include URLs in error messages");
  einfo (INFO, "  And re-enabled with:");
  einfo (INFO, "    --provide-urls            Include URLs in error messages");
}

static bool
process_arg (const char * arg, const char ** argv, const uint argc, uint * next)
{
  if (arg[0] == '-')
    ++ arg;
  if (arg[0] == '-')
    ++ arg;

  if (startswith (arg, "skip-"))
    {
      arg += strlen ("skip-");

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

      /* Do not fail if we do not recognise the test name.  It may be from a
	 future version of annocheck, and it just so happens that a test is
	 running this version by mistake.  */
      einfo (INFO, "ignoring unrecognized test name in --skip option: %s", arg);
      return true;
    }

  if (startswith (arg, "test-"))
    {
      arg += strlen ("test-");

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

      if (streq (arg, "unicode-all"))
	{
	  fail_for_all_unicode.option_value = true;
	  fail_for_all_unicode.option_set = true;
	  tests[TEST_UNICODE].enabled = true;
	  return true;
	}

      if (streq (arg, "unicode-suspicious"))
	{
	  fail_for_all_unicode.option_value = false;
	  fail_for_all_unicode.option_set = true;
	  tests[TEST_UNICODE].enabled = true;
	  return true;
	}

      return false;
    }

  if (streq (arg, "enable-hardened") || streq (arg, "enable"))
    {
      disabled = false;
      return true;
    }

  if (streq (arg, "disable-hardened") || streq (arg, "disable"))
    {
      disabled = true;
      return true;
    }

  if (streq (arg, "ignore-gaps"))
    {
      ignore_gaps = true;
      return true;
    }

  if (streq (arg, "report-gaps"))
    {
      ignore_gaps = false;
      return true;
    }

  if (streq (arg, "fixed-format-messages"))
    {
      fixed_format_messages = true;
      return true;
    }

  if (streq (arg, "disable-colour") || streq (arg, "disable-color"))
    {
      enable_colour = false;
      return true;
    }

  if (streq (arg, "enable-colour") || streq (arg, "enable-color"))
    {
      enable_colour = true;
      return true;
    }

  if (streq (arg, "provide-urls") || streq (arg, "provide-url"))
    {
      provide_url.option_value = true;
      provide_url.option_set = true;
      return true;	
    }

  if (streq (arg, "no-urls"))
    {
      provide_url.option_value = false;
      provide_url.option_set = true;
      return true;	
    }

  if (streq (arg, "full-filenames") || streq (arg, "full-filename"))
    {
      full_filename.option_value = true;
      full_filename.option_set = true;
      return true;
    }

  if (streq (arg, "base-filenames") || streq (arg, "base-filename"))
    {
      full_filename.option_value = false;
      full_filename.option_set = true;
      return true;
    }

  /* Accept both --profile-<name> and --profile=<name>.  */
  if (startswith (arg, "profile"))
    {
      arg += strlen ("profile-");

      uint i;

      for (i = ARRAY_SIZE (profiles); i--;)
	if (streq (arg, profiles[i].name))
	  {
	    set_profile (i);
	    return true;
	  }

      if (streq (arg, "none") || streq (arg, "default"))
	set_profile (PROFILE_NONE);
      else
	einfo (ERROR, "Argument to --profile- option not recognised");

      /* Consume the argument so that the annocheck framework does not mistake it for the -p option.  */
      return true;
    }

  return false;
}

/* -------------------------------------------------------------------------------------------- */

static struct checker hardened_checker =
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

#ifndef LIBANNOCHECK

static __attribute__((constructor)) void
register_checker (void)
{
  if (! annocheck_add_checker (& hardened_checker, ANNOBIN_VERSION / 100))
    disabled = true;
}

#else /* LIBANNOCHECK defined */

#include "libannocheck.h"

typedef struct libannocheck_internals
{
  const char * filepath;
  const char * debugpath;

  libannocheck_test     tests[TEST_MAX];

} libannocheck_internals;

/* For now we just support one handle at a time.  */
static libannocheck_internals *  cached_handle;
static const char *              cached_reason;

static libannocheck_error
set_error (libannocheck_error err, const char * reason)
{
  cached_reason = reason;
  return err;
}

static bool
verify_handle (void * handle)
{
  // FIXME: Add more sanity tests ?
  return handle == cached_handle;
}

struct libannocheck_internals *
libannocheck_init (unsigned int  version,
		   const char *  filepath,
		   const char *  debugpath)
{
  if (version < libannocheck_version)
    return (struct libannocheck_internals *) set_error (libannocheck_error_bad_version, "version number too small");

  if (filepath == NULL || * filepath == 0)
    return (struct libannocheck_internals *) set_error (libannocheck_error_file_not_found, "filepath empty");

  static bool checker_initialised = false;
  if (! checker_initialised)
    {
      if (! annocheck_add_checker (& hardened_checker, ANNOBIN_VERSION / 100))
	return (struct libannocheck_internals *) set_error (libannocheck_error_not_supported, "unable to initialise checker");

      if (elf_version (EV_CURRENT) == EV_NONE)
	return (struct libannocheck_internals *) set_error (libannocheck_error_not_supported, "unable to initialise ELF library");

      checker_initialised = true;
    }

  libannocheck_internals * handle  = calloc (1, sizeof * handle);

  if (handle == NULL)
    return (struct libannocheck_internals *) set_error (libannocheck_error_out_of_memory, "allocating new handle");

  handle->filepath = strdup (filepath);
  if (debugpath)
    handle->debugpath = strdup (debugpath);

  unsigned int i;
  for (i = 0; i < TEST_MAX; i++)
    {
      handle->tests[i].name = tests[i].name;
      handle->tests[i].description = tests[i].description;
      handle->tests[i].doc_url = tests[i].doc_url;
      handle->tests[i].enabled = true;
      handle->tests[i].state = libannocheck_test_state_not_run;
    }

  cached_handle = handle;
  cached_reason = NULL;
  return handle;
}

libannocheck_error
libannocheck_finish (struct libannocheck_internals * handle)
{
  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "cannot release handle");

  free ((void *) handle->filepath);
  free ((void *) handle->debugpath);
  free ((void *) handle);

  cached_handle = NULL;
  return libannocheck_error_none;
}

const char *
libannocheck_get_error_message (struct libannocheck_internals * handle ATTRIBUTE_UNUSED,
				enum libannocheck_error err)
{
  if (cached_reason != NULL)
    return cached_reason;

  switch (err)
    {
    case libannocheck_error_none: return "no error";
    case libannocheck_error_bad_arguments: return "bad arguments";
    case libannocheck_error_bad_handle: return "bad handle";
    case libannocheck_error_bad_version: return "bad version";
    case libannocheck_error_debug_file_not_found: return "debug file not found";
    case libannocheck_error_file_corrupt: return "file corrupt";
    case libannocheck_error_file_not_ELF: return "not an ELF file";
    case libannocheck_error_file_not_found: return "file not found";
    case libannocheck_error_not_supported: return "operation not supported";
    case libannocheck_error_out_of_memory: return "out of memory";
    case libannocheck_error_profile_not_known: return "profile not known";
    case libannocheck_error_test_not_found: return "test not found";
    default: return "INTERNAL ERROR - error code not recognised";
    }
}

unsigned int
libannocheck_get_version (void)
{
  return libannocheck_version;
}

libannocheck_error
libannocheck_get_known_tests (struct libannocheck_internals * handle, libannocheck_test ** tests_return, unsigned int * num_tests_return)
{
  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  if (tests_return == NULL || num_tests_return == NULL)
    return set_error (libannocheck_error_bad_arguments, "NULL passed as an argument");

  * tests_return = handle->tests;
  * num_tests_return = TEST_MAX;

  return libannocheck_error_none;
}

libannocheck_error
libannocheck_enable_all_tests (struct libannocheck_internals * handle)
{
  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  unsigned int i;

  for (i = 0; i < TEST_MAX; i++)
    handle->tests[i].enabled = true;

  return libannocheck_error_none;
}

libannocheck_error
libannocheck_disable_all_tests (struct libannocheck_internals * handle)
{
  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  unsigned int i;

  for (i = 0; i < TEST_MAX; i++)
    handle->tests[i].enabled = false;

  return libannocheck_error_none;
}

static libannocheck_test *
find_test (libannocheck_internals * handle, const char * name)
{
  unsigned int i;

  for (i = 0; i < TEST_MAX; i++)
    if (streq (handle->tests[i].name, name))
      return handle->tests + i;

  return NULL;
}

libannocheck_error
libannocheck_enable_test (libannocheck_internals * handle, const char * name)
{
  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  if (name == NULL)
    return set_error (libannocheck_error_bad_arguments, "NAME is NULL");

  libannocheck_test * test;

  if ((test = find_test (handle, name)) == NULL)
    return set_error (libannocheck_error_test_not_found, "no such test");

  test->enabled = true;

  return libannocheck_error_none;
}

libannocheck_error
libannocheck_disable_test (libannocheck_internals * handle, const char * name)
{
  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  if (name == NULL)
    return set_error (libannocheck_error_bad_arguments, "NAME is NULL");

  libannocheck_test * test;

  if ((test = find_test (handle, name)) == NULL)
    return set_error (libannocheck_error_test_not_found, "no such test");

  test->enabled = false;

  return libannocheck_error_none;
}

libannocheck_error
libannocheck_enable_profile (libannocheck_internals * handle, const char * name)
{
  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  if (name == NULL)
    return set_error (libannocheck_error_bad_arguments, "NAME is NULL");

  unsigned int i;

  for (i = ARRAY_SIZE (profiles); i--;)
    {
      if (streq (name, profiles[i].name))
	{
	  unsigned int j;

	  for (j = 0; j < MAX_DISABLED; j++)
	    {
	      enum test_index index = profiles[i].disabled_tests[j];

	      if (index == TEST_NOTES)
		break;
	      handle->tests[index].enabled = false;
	    }

	  for (j = 0; j < MAX_DISABLED; j++)
	    {
	      enum test_index index = profiles[i].enabled_tests[j];

	      if (index == TEST_NOTES)
		break;
	      handle->tests[index].enabled = true;
	    }

	  return libannocheck_error_none;
	}
    }

    return set_error (libannocheck_error_profile_not_known, "no such profile");
}

libannocheck_error
libannocheck_get_known_profiles (libannocheck_internals *  handle,
				 const char ***      profiles_return,
				 unsigned int *            num_profiles_return)
{
  static const char * profiles[4] =
    { "el7", "el8", "el9", "rawhide" };

  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  if (profiles_return == NULL || num_profiles_return == NULL)
    return set_error (libannocheck_error_bad_arguments, "NULL passed as argument");

  * profiles_return = profiles;
  * num_profiles_return = 4;

  return libannocheck_error_not_supported;
}

libannocheck_error
libannocheck_run_tests (libannocheck_internals * handle,
			unsigned int * num_fail_return,
			unsigned int * num_mayb_return)
{
  if (! verify_handle (handle))
    return set_error (libannocheck_error_bad_handle, "unrecognised handle");

  if (num_fail_return == NULL || num_mayb_return == NULL)
    return set_error (libannocheck_error_bad_arguments, "NULL passed as argument");

  add_file (handle->filepath);
  if (handle->debugpath)
    set_debug_file (handle->debugpath);

  unsigned int i;
  for (i = 0; i < TEST_MAX; i++)
    {
      tests[i].enabled = handle->tests[i].enabled;
      tests[i].state   = STATE_UNTESTED;
    }

  (void) process_files ();

  * num_fail_return = per_file.num_fails;
  * num_mayb_return = per_file.num_maybes;

  return libannocheck_error_none;
}

#endif /* ENABLE_LIBANNOCHECK */
