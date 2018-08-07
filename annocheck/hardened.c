/* Checks the hardened status of the given file. 
   Copyright (c) 2018 Red Hat.

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

#include "annocheck.h"

/* Set by the constructor.  */
static bool disabled = false;

/* Can be changed by a command line option.  */
static bool ignore_gaps = false;

/* These are initialised on a per-input-file basis by start().  */
static int  e_type;
static int  e_machine;
static bool is_little_endian;
static bool debuginfo_file;
static int  num_fails;
static int  num_maybes;
static int  gcc_version;

typedef struct hardened_note_data
{
  ulong         start;
  ulong         end;
} hardened_note_data;

static hardened_note_data *  ranges = NULL;
static unsigned              num_allocated_ranges = 0;
static unsigned              next_free_range = 0;
#define RANGE_ALLOC_DELTA    16

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
  TEST_CF_PROTECTION,
  TEST_DYNAMIC_SEGMENT,
  TEST_FORTIFY,
  TEST_GLIBCXX_ASSERTIONS,
  TEST_GNU_RELRO,
  TEST_GNU_STACK,
  TEST_OPTIMIZATION,
  TEST_PIC,
  TEST_RUN_PATH,
  TEST_RWX_SEG,
  TEST_STACK_CLASH,
  TEST_STACK_PROT,
  TEST_STACK_REALIGN,
  TEST_TEXTREL,
  TEST_THREADS,
  TEST_WRITEABLE_GOT,
  
  TEST_MAX
};

static void show_BIND_NOW           (annocheck_data *, test *);
static void show_CF_PROTECTION      (annocheck_data *, test *);
static void show_DYNAMIC_SEGMENT    (annocheck_data *, test *);
static void show_FORTIFY            (annocheck_data *, test *);
static void show_GLIBCXX_ASSERTIONS (annocheck_data *, test *);
static void show_GNU_RELRO          (annocheck_data *, test *);
static void show_GNU_STACK          (annocheck_data *, test *);
static void show_OPTIMIZATION       (annocheck_data *, test *);
static void show_PIC                (annocheck_data *, test *);
static void show_RUN_PATH           (annocheck_data *, test *);
static void show_RWX_SEG            (annocheck_data *, test *);
static void show_STACK_CLASH        (annocheck_data *, test *);
static void show_STACK_PROT         (annocheck_data *, test *);
static void show_STACK_REALIGN      (annocheck_data *, test *);
static void show_TEXTREL            (annocheck_data *, test *);
static void show_THREADS            (annocheck_data *, test *);
static void show_WRITEABLE_GOT      (annocheck_data *, test *);

#define TEST(name,upper,description) \
  [ TEST_##upper ] = { true, 0, 0, 0, #name, description, show_ ## upper }

/* Array of tests to run.  Default to enabling them all.
   The result field is initialised in the start() function.  */
static test tests [TEST_MAX] =
{
  TEST (bind-now,           BIND_NOW,           "Linked with -Wl,-z,now"),
  TEST (cf-protection,      CF_PROTECTION,      "Compiled with -fcf-protection=all (x86 only, gcc 8 only)"),
  TEST (dynamic-segment,    DYNAMIC_SEGMENT,    "There is a dynamic segment/section present"),
  TEST (fortify,            FORTIFY,            "Compiled with -D_FORTIFY_SOURCE=2"),
  TEST (glibcxx-assertions, GLIBCXX_ASSERTIONS, "Compield with -D_GLIBCXX_ASSERTIONS"),
  TEST (gnu-relro,          GNU_RELRO,          "The relocations for the GOT are not writeable"),
  TEST (gnu-stack,          GNU_STACK,          "The stack is not executable"),
  TEST (optimization,       OPTIMIZATION,       "Compiled with at least -O2"),
  TEST (pic,                PIC,                "Compiled with -fPIC or fPIE"),
  TEST (run-path,           RUN_PATH,           "All runpath entries are under /usr"),
  TEST (rwx-seg,            RWX_SEG,            "There are no segments that are both writeable and executable"),
  TEST (stack-clash,        STACK_CLASH,        "Compiled with -fstack-clash-protection (not ARM)"),
  TEST (stack-prot,         STACK_PROT,         "Compiled with -fstack-protector-strong"),
  TEST (stack-realign,      STACK_REALIGN,      "Compiled with -mstackrealign (i686 only)"),
  TEST (textrel,            TEXTREL,            "There are no text relocations in the binary"),
  TEST (threads,            THREADS,            "Compiled with -fexceptions"),
  TEST (writeable-got,      WRITEABLE_GOT,      "The .got section is not writeable"),
};


static void
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
  debuginfo_file = false;
  gcc_version = -1;
  if (num_allocated_ranges)
    {
      free (ranges);
      ranges = NULL;
      next_free_range = num_allocated_ranges = 0;
    }

  num_fails = 0;
  num_maybes = 0;

  if (data->is_32bit)
    {
      Elf32_Ehdr * hdr = elf32_getehdr (data->elf);

      e_type = hdr->e_type;
      e_machine = hdr->e_machine;
      is_little_endian = hdr->e_ident[EI_DATA] != ELFDATA2MSB;
    }
  else
    {
      Elf64_Ehdr * hdr = elf64_getehdr (data->elf);
      
      e_type = hdr->e_type;
      e_machine = hdr->e_machine;
      is_little_endian = hdr->e_ident[EI_DATA] != ELFDATA2MSB;
    }
}

static bool
interesting_sec (annocheck_data *     data,
		 annocheck_section *  sec)
{
  if (disabled)
    return false;

  /* .dwz files have a .gdb_index section.  */
  if (streq (sec->secname, ".gdb_index"))
    debuginfo_file = true;

  if (streq (sec->secname, ".text"))
    {
      /* Separate debuginfo files have a .text section with a non-zero
	 size but no contents!  */
      if (sec->shdr.sh_type == SHT_NOBITS && sec->shdr.sh_size > 0)
	debuginfo_file = true;

      return false;
    }
  else if (debuginfo_file)
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

  /* These types of section need further processing.  */
  return sec->shdr.sh_type == SHT_DYNAMIC
    || sec->shdr.sh_type == SHT_NOTE
    || sec->shdr.sh_type == SHT_STRTAB;
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
  if (component_name == NULL)
    return false;

  if (strstr (component_name, "component: "))
    component_name += strlen ("component: ");

  if (streq (component_name, "elf_init.c")
      || streq (component_name, "init.c"))
    {
      einfo (VERBOSE2, "skipping test %s for component %s", tests[check].name, component_name);
      return true;
    }

  /* We know that some glibc startup functions cannot be compiled
     with stack protection enabled.  So do not complain about them.  */
  static const char * skip_these_funcs[] =
    {
      "_init",
      "_fini",
      "__libc_csu_init",
      "__libc_csu_fini",
      "_start"
    };
  int i;

  for (i = ARRAY_SIZE (skip_these_funcs); i--;)
    if (streq (component_name, skip_these_funcs[i]))
      {
	einfo (VERBOSE2, "skipping test %s for component %s", tests[check].name, component_name);
	return true;
      }

  return false;
}

/* Returns true iff addr1 and addr2 are in the same section.  */

static bool
same_section (annocheck_data * data,
	      ulong            addr1,
	      ulong            addr2)
{
  Elf_Scn * addr1_scn = NULL;
  Elf_Scn * addr2_scn = NULL;
  Elf_Scn * scn = NULL;

  if (data->is_32bit)
    {
      while ((scn = elf_nextscn (data->elf, scn)) != NULL)
	{
	  Elf32_Shdr * shdr = elf32_getshdr (scn);

	  if (addr1_scn == NULL
	      && shdr->sh_addr <= addr1 && ((shdr->sh_addr + shdr->sh_size) >= addr1))
	    addr1_scn = scn;

	  if (addr2_scn == NULL
	      && shdr->sh_addr <= addr2 && ((shdr->sh_addr + shdr->sh_size) >= addr2))
	    addr2_scn = scn;
	}
    }
  else
    {
      while ((scn = elf_nextscn (data->elf, scn)) != NULL)
	{
	  Elf64_Shdr * shdr = elf64_getshdr (scn);

	  if (addr1_scn == NULL
	      && shdr->sh_addr <= addr1 && ((shdr->sh_addr + shdr->sh_size) >= addr1))
	    addr1_scn = scn;

	  if (addr2_scn == NULL
	      && shdr->sh_addr <= addr2 && ((shdr->sh_addr + shdr->sh_size) >= addr2))
	    addr2_scn = scn;
	}
    }

  return addr1_scn == addr2_scn && addr1_scn != NULL;
}

static void
record_range (ulong start, ulong end)
{
  if (start == end)
    return;

  if (next_free_range >= num_allocated_ranges)
    {
      num_allocated_ranges += RANGE_ALLOC_DELTA;
      if (ranges == NULL)
	ranges = xmalloc (num_allocated_ranges * sizeof ranges[0]);
      else
	ranges = xrealloc (ranges, num_allocated_ranges * sizeof ranges[0]);
    }

  /* Nothing clever here.  Just record the data.  */
  assert (start < end);
  ranges[next_free_range].start = start;
  ranges[next_free_range].end   = end;
  next_free_range ++;
}

static int
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
  return 0;
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
	
static bool
walk_notes (annocheck_data *     data,
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

	  if (is_little_endian)
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
	  if (is_little_endian)
	    {
	      start = descdata[0] | (descdata[1] << 8) | (descdata[2] << 16) | (descdata[3] << 24);
	      end   = descdata[4] | (descdata[5] << 8) | (descdata[6] << 16) | (descdata[7] << 24);
	    }
	  else
	    {
	      start = descdata[3] | (descdata[2] << 8) | (descdata[1] << 16) | (descdata[0] << 24);
	      end   = descdata[7] | (descdata[6] << 8) | (descdata[5] << 16) | (descdata[4] << 24);
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
	  einfo (FAIL, "%s: Corrupt annobin note, start address %#lx > end address %#lx (%d)",
		 data->filename, start, end, is_little_endian);
	  return true;
	}

      note_data->start = start;
      note_data->end   = end;

      if (e_type != ET_REL && ! ignore_gaps)
	{
	  /* Notes can occur in any order and may be spread across multiple note
	     sections.  So we record the range covered here and then check for
	     gaps once we have examined all of the notes.  */
	  record_range (start, end);
	}
    }

  /* We skip notes for empty ranges unless we are dealing with unrelocated object files.  */
  if (e_type != ET_REL && note_data->start == note_data->end)
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
      return false;
    }

  switch (* attr)
    {
    case GNU_BUILD_ATTRIBUTE_TOOL:
      if (value != -1)
	einfo (VERBOSE, "ICE: The tool note should have a string attribute");
      else
	{
	  /* Parse the tool attribute looking for the version of gcc used to build the component.  */
	  const char * gcc = strstr (attr, "gcc");
	  if (gcc)
	    {
	      /* FIXME: This assumes that the tool string looks like: "gcc 7.x.x......"  */
	      unsigned int version = (unsigned int) strtoul (gcc + 4, NULL, 10);

	      report_i (VERBOSE2, "%s: (%s) built-by gcc version %u",
			data, sec, note_data, prefer_func_name, version);

	      if (gcc_version == -1)
		gcc_version = version;
	      else if (gcc_version != version)
		{
		  einfo (VERBOSE, "%s: Warning: Multiple versions of gcc were used to build this file - the highest version will be used",
			 data->filename);
		  if (gcc_version < version)
		    gcc_version = version;
		}
	    }
	}
      break;

    case GNU_BUILD_ATTRIBUTE_PIC:
      /* Convert the pic value into a pass/fail result.  */
      switch (value)
	{
	case -1:
	default:
	  report_i (VERBOSE, "%s: mayb: (%s): unexpected value for PIC note (%x)",
		    data, sec, note_data, prefer_func_name, value);
	  tests[TEST_PIC].num_maybe ++;
	  break;

	case 0:
	  report_s (INFO, "%s: fail: (%s): compiled without -fPIC/-fPIE",
		  data, sec, note_data, prefer_func_name, NULL);
	  tests[TEST_PIC].num_fail ++;
	  break;

	case 1:
	case 2:
	  /* Compiled wth -fpic not -fpie.  */
	  if (e_type == ET_EXEC)
	    {
	      report_s (INFO, "%s: fail: (%s): compiled with -fPIC rather than -fPIE",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_PIC].num_fail ++;
	    }
	  else
	    {
	      report_s (VERBOSE2, "%s: pass: (%s): compiled with -fPIC/-fPIE",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_PIC].num_pass ++;
	    }
	  break;

	case 3:
	case 4:
	  report_s (VERBOSE2, "%s: pass: (%s): compiled with -fPIE",
		  data, sec, note_data, prefer_func_name, NULL);
	  tests[TEST_PIC].num_pass ++;
	  break;
	}
      break;

    case GNU_BUILD_ATTRIBUTE_STACK_PROT:
      switch (value)
	{
	case -1:
	default:
	  report_i (VERBOSE, "%s: mayb: (%s): unexpected value for stack protection note (%x)",
		  data, sec, note_data, prefer_func_name, value);
	  tests[TEST_STACK_PROT].num_maybe ++;
	  break;
	  
	case 0: /* NONE */
	  if (skip_check (TEST_STACK_PROT, get_component_name (data, sec, note_data, prefer_func_name)))
	    return true;
	  report_s (INFO, "%s: fail: (%s): No stack protection enabled",
		  data, sec, note_data, prefer_func_name, NULL);
	  tests[TEST_STACK_PROT].num_fail ++;
	  break;

	case 1: /* BASIC (funcs using alloca or with local buffers > 8 bytes) */
	case 4: /* EXPLICIT */
	  report_s (INFO, "%s: fail: (%s): Insufficient stack protection: %s",
		  data, sec, note_data, prefer_func_name, stack_prot_type (value));
	  tests[TEST_STACK_PROT].num_fail ++;
	  break;

	case 2: /* ALL */
	case 3: /* STRONG */
	  report_s (VERBOSE2, "%s: pass: (%s): %s enabled",
		  data, sec, note_data, prefer_func_name, stack_prot_type (value));
	  tests[TEST_STACK_PROT].num_pass ++;
	  break;
	}
      break;

    case 'c':
      if (streq (attr, "cf_protection"))
	{
	  if (e_machine != EM_386 && e_machine != EM_X86_64)
	    break;

	  switch (value)
	    {
	    case -1:
	    default:
	      report_i (VERBOSE, "%s: mayb: (%s): unexpected value for cf-protection note (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_CF_PROTECTION].num_maybe ++;
	      break;

	    case 4: /* CF_FULL.  */
	    case 8: /* CF_FULL | CF_SET */
	      report_i (VERBOSE2, "%s: pass: (%s): cf-protection enabled (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_CF_PROTECTION].num_pass ++;
	      break;

	    case 2: /* CF_BRANCH: Branch but not return.  */
	    case 6: /* CF_BRANCH | CF_SET */
	      report_s (VERBOSE, "%s: fail: (%s): Only compiled with -fcf-protection=branch",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_CF_PROTECTION].num_fail ++;
	      break;

	    case 3: /* CF_RETURN: Return but not branch.  */
	    case 7: /* CF_RETURN | CF_SET */
	      report_s (INFO, "%s: fail: (%s): Only compiled with -fcf-protection=return",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_CF_PROTECTION].num_fail ++;
	      break;

	    case 1: /* CF_NONE: No protection. */
	    case 5: /* CF_NONE | CF_SET */
	      if (skip_check (TEST_CF_PROTECTION, get_component_name (data, sec, note_data, prefer_func_name)))
		return true;
	      report_s (INFO, "%s: fail: (%s): Compiled without -fcf-protection",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_CF_PROTECTION].num_fail ++;
	      break;
	    }
	}
      break;

    case 'F':
      if (streq (attr, "FORTIFY"))
	{
	  switch (value)
	    {
	    case -1:
	    default:
	      report_i (VERBOSE, "%s: mayb: (%s): unexpected value for fortify note (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_FORTIFY].num_maybe ++;
	      break;

	    case 0xff:
	      report_s (VERBOSE, "%s: mayb: (%s): -D_FORTIFY_SOURCE setting not recorded",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_FORTIFY].num_maybe ++;
	      break;

	    case 0:
	      if (skip_check (TEST_FORTIFY, get_component_name (data, sec, note_data, prefer_func_name)))
		return true;
	      /* Fall through.  */
	    case 1:
	      report_i (INFO, "%s: fail: (%s): Insufficient value for -D_FORTIFY_SOURCE: %d",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_FORTIFY].num_fail ++;
	      break;

	    case 2:
	      report_s (VERBOSE2, "%s: pass: (%s): -D_FORTIFY_SOURCE=2",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_FORTIFY].num_pass ++;
	      break;
	    }	      
	}
      break;

    case 'G':
      if (streq (attr, "GOW"))
	{
	  if (value == -1)
	    {
	      report_i (VERBOSE, "%s: mayb: (%s): unexpected value for optimize note (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_OPTIMIZATION].num_maybe ++;
	    }
	  else
	    {
	      value = (value >> 9) & 3;

	      if (value == 0 || value == 1)
		{
		  report_i (INFO, "%s: fail: (%s): Insufficient optimization level: -O%d",
			  data, sec, note_data, prefer_func_name, value);
		  tests[TEST_OPTIMIZATION].num_fail ++;
		}
	      else /* value == 2 || value == 3 */
		{
		  report_i (VERBOSE2, "%s: pass: (%s): Sufficient optimization level: -O%d",
			  data, sec, note_data, prefer_func_name, value);
		  tests[TEST_OPTIMIZATION].num_pass ++;
		}
	    }
	  break;
	}
      else if (streq (attr, "GLIBCXX_ASSERTIONS"))
	{
	  switch (value)
	    {
	    case 0:
	      if (skip_check (TEST_GLIBCXX_ASSERTIONS, get_component_name (data, sec, note_data, prefer_func_name)))
		return true;
	      report_s (INFO, "%s: fail: (%s): Compiled without -D_GLIBCXX_ASSERTIONS", 
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_GLIBCXX_ASSERTIONS].num_fail ++;
	      break;

	    case 1:
	      report_s (VERBOSE2, "%s: pass: (%s): Compiled with -D_GLIBCXX_ASSERTIONS", 
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_GLIBCXX_ASSERTIONS].num_pass ++;
	      break;

	    default:
	      report_i (VERBOSE, "%s: mayb: (%s): unexpected value for glibcxx_assertions note (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_GLIBCXX_ASSERTIONS].num_maybe ++;
	      break;
	    }
	}
      break;

    case 's':
      if (streq (attr, "stack_clash"))
	{
	  if (e_machine == EM_ARM)
	    break;

	  switch (value)
	    {
	    case 0:
	      report_s (INFO, "%s: fail: (%s): Compiled without -fstack-clash-protection",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_STACK_CLASH].num_fail ++;
	      break;

	    case 1:
	      report_s (VERBOSE2, "%s: pass: (%s): Compiled with -fstack-clash-protection",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_STACK_CLASH].num_pass ++;
	      break;

	    default:
	      report_i (VERBOSE, "%s: mayb: (%s): unexpected value for stack-clash note (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_STACK_CLASH].num_maybe ++;
	      break;
	    }
	}
      else if (streq (attr, "stack_realign"))
	{
	  if (e_machine != EM_386)
	    break;

	  switch (value)
	    {
	    case -1:
	      report_i (VERBOSE, "%s: mayb: (%s): unexpected value for stack realign note (%x)",
		      data, sec, note_data, prefer_func_name, value);
	      tests[TEST_STACK_REALIGN].num_maybe ++;
	      break;

	    case 0:
	      report_s (INFO, "%s: fail: (%s): Compiled without -fstack-realign",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_STACK_REALIGN].num_fail ++;
	      break;

	    case 1:
	      report_s (VERBOSE2, "%s: pass: (%s): Compiled with -fstack-realign",
		      data, sec, note_data, prefer_func_name, NULL);
	      tests[TEST_STACK_REALIGN].num_pass ++;
	      break;
	    }
	}
      break;
      
    default:
      break;
    }

  return true;
}

static bool
check_note_section (annocheck_data *    data,
		    annocheck_section * sec)
{
  if (const_strneq (sec->secname, GNU_BUILD_ATTRS_SECTION_NAME))
    {
      hardened_note_data hard_data;

      hard_data.start = 0;
      hard_data.end = 0;

      return annocheck_walk_notes (data, sec, walk_notes, (void *) & hard_data);
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
  size_t num_entries = sec->shdr.sh_size / sec->shdr.sh_entsize;

  /* Walk the dynamic tags.  */
  while (num_entries --)
    {
      GElf_Dyn   dynmem;
      GElf_Dyn * dyn = gelf_getdyn (sec->data, num_entries, & dynmem);

      if (dyn == NULL)
	break;

      if (dyn->d_tag == DT_BIND_NOW)
	tests[TEST_BIND_NOW].num_pass ++;

      else if (dyn->d_tag == DT_FLAGS
	       && dyn->d_un.d_val & DF_BIND_NOW)
	tests[TEST_BIND_NOW].num_pass ++;

      if (dyn->d_tag == DT_TEXTREL)
	tests[TEST_TEXTREL].num_fail ++;

      if (dyn->d_tag == DT_RPATH || dyn->d_tag == DT_RUNPATH)
	if (not_rooted_at_usr (elf_strptr (data->elf, sec->shdr.sh_link, dyn->d_un.d_val)))
	  tests[TEST_RUN_PATH].num_fail ++;
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
    case SHT_NOTE:    return check_note_section (data, sec);
    case SHT_STRTAB:  return check_string_section (data, sec);
    case SHT_DYNAMIC: return check_dynamic_section (data, sec);
    default:          break;
    }

  return true;
}

static bool
interesting_seg (annocheck_data *    data,
		 annocheck_segment * seg)
{
  if (disabled)
    return false;

  switch (seg->phdr->p_type)
    {
    case PT_GNU_RELRO:
      tests[TEST_GNU_RELRO].num_pass ++;
      break;

    case PT_GNU_STACK:
      tests[TEST_GNU_STACK].num_pass ++;
      break;

    case PT_DYNAMIC:
      tests[TEST_DYNAMIC_SEGMENT].num_pass ++;
      break;

    default:
      break;
    }

  if ((seg->phdr->p_flags & (PF_X | PF_W | PF_R)) == (PF_X | PF_W | PF_R)
      && seg->phdr->p_type != PT_GNU_STACK)
    {
      einfo (VERBOSE, "%s: fail: seg %d has Read, Write and eXecute flags\n",
	     data->filename, seg->number);
      tests[TEST_RWX_SEG].num_fail ++;
    }

  return false;
}

static void
fail (annocheck_data * data, const char * message)
{
  einfo (INFO, "%s: FAIL: %s", data->filename, message);
  ++ num_fails;
}

static void
maybe (annocheck_data * data, const char * message)
{
  einfo (INFO, "%s: MAYB: %s", data->filename, message);
  ++ num_maybes;
}

static void
pass (annocheck_data * data, const char * message)
{
  einfo (VERBOSE2, "%s: pass: %s", data->filename, message);
}

static void
check_for_gaps (annocheck_data * data)
{
  bool gap_found = false;

  assert (! ignore_gaps);

  if (next_free_range < 2)
    return;

  /* Sort the ranges array.  */
  qsort (ranges, next_free_range, sizeof ranges[0], compare_range);

  hardened_note_data current = ranges[0];
  
  /* Scan the ranges array.  */
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

	  if (same_section (data, gap.start, gap.end))
	    {
	      const char * sym = annocheck_find_symbol_for_address_range (data, NULL, gap.start, gap.end, false);

	      if ((sym == NULL || strstr (sym, ".end"))
		  && gap.start != align (gap.start, 16))
		{
		  sym = annocheck_find_symbol_for_address_range (data, NULL, align (gap.start, 16), gap.end, false);
		  if (sym)
		    gap.start = align (gap.start, 16);
		}

	      if (sym && skip_check (TEST_MAX, sym))
		continue;

	      gap_found = true;
	      if (! BE_VERBOSE)
		break;

	      if (sym)
		einfo (VERBOSE, "%s: gap:  (%lx..%lx probable component: %s) in annobin notes",
		       data->filename, gap.start, gap.end, sym);
	      else
		einfo (VERBOSE, "%s: gap:  (%lx..%lx) in annobin notes",
		       data->filename, gap.start, gap.end);
	    }

	  /* We have found a gap, so reset the current range.  */
	  current = ranges[i];
	}
    }

  if (!gap_found)
    {
      pass (data, "No gaps found");
      return;
    }

  if (! BE_VERBOSE)
    maybe (data, "Gaps were detected in the annobin coverage.  Run with -v to list");
  else
    maybe (data, "Gaps were detected in the annobin coverage");
}

static void
show_BIND_NOW (annocheck_data * data, test * results)
{
  /* Only executables need to have their binding checked.  */
  if (e_type != ET_EXEC)
    return;

  if (results->num_pass == 0 || results->num_fail > 0 || results->num_maybe > 0)
    fail (data, "Not linked with -Wl,-z,now");
  else
    pass (data, "Linked with -Wl,-z,now");
}

static void
show_DYNAMIC_SEGMENT (annocheck_data * data, test * results)
{
  /* Relocateable object files do not have dynamic segments.  */
  if (e_type == ET_REL)
    return;

  if (results->num_pass == 0 || results->num_fail > 0 || results->num_maybe > 0)
    maybe (data, "Dynamic segment is absent");
  else
    pass (data, "Dynamic segment is present");
}

static void
show_GNU_RELRO (annocheck_data * data, test * results)
{
  /* Relocateable object files are not yet linked.  */
  if (e_type == ET_REL)
    return;

  if (results->num_pass == 0 || results->num_fail > 0 || results->num_maybe > 0)
    fail (data, "Linked without -Wl,-z,relro");
  else
    pass (data, "Linked with -Wl,-z,relro");
}

static void
show_GNU_STACK (annocheck_data * data, test * results)
{
  /* Relocateable object files do not have a stack section.  */
  if (e_type == ET_REL)
    return;

  if (results->num_pass == 0 || results->num_fail > 0 || results->num_maybe > 0)
    fail (data, "Executable stack found");
  else
    pass (data, "Stack not executable");
}

static void
show_RWX_SEG (annocheck_data * data, test * results)
{
  /* Relocateable object files do not have segments.  */
  if (e_type == ET_REL)
    return;

  if (results->num_fail > 0 || results->num_maybe > 0)
    fail (data, "A segment with RWX permissions was found");
  else
    pass (data, "No RWX segments found");
}

static void
show_TEXTREL (annocheck_data * data, test * results)
{
  /* Relocateable object files can have text relocations.  */
  if (e_type == ET_REL)
    return;

  if (results->num_fail > 0 || results->num_maybe > 0)
    fail (data, "Text relocations found");
  else
    pass (data, "No text relocations found");
}

static void
show_RUN_PATH (annocheck_data * data, test * results)
{
  /* Relocateable object files do not need a runtime path.  */
  if (e_type == ET_REL)
    return;

  if (results->num_fail > 0 || results->num_maybe > 0)
    fail (data, "DT_RPATH/DT_RUNPATH contains directories not starting with /usr");
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
  /* Relocateable object files do not have a GOT.  */
  if (e_type == ET_REL)
    return;

  if (results->num_fail > 0 || results->num_maybe > 0)
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
	fail (data, "Parts of the binary were compiled without sufficient optimization");
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
	fail (data, "Parts of the binary were compiled without the proper PIC option");
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
  else
    {
      maybe (data, "The PIC/PIE setting was not recorded");
    }
}

static void
show_STACK_PROT (annocheck_data * data, test * results)
{
  if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	fail (data, "Parts of the binary were compiled without suffcient stack protection");
      else
	fail (data, "The binary was compiled without -fstack-protector-strong");
    }
  else if (results->num_maybe > 0)
    {
      if (results->num_pass > 0)
	{
	  if (! BE_VERBOSE)
	    maybe (data, "Some parts of the binary do not record the stack protection setting.  Run with -v to see where");
	  else
	    maybe (data, "Some parts of the binary do not record the stack protection setting");
	}
      else
	maybe (data, "The stack protections setting was not recorded");
    }
  else if (results->num_pass > 0)
    {
      pass (data, "Compiled with sufficient stack protection");
    }
  else
    {
      maybe (data, "The stack protection setting was not recorded");
    }
}

static void
show_STACK_CLASH (annocheck_data * data, test * results)
{
  /* The ARM does not have stack clash protection support.  */
  if (e_machine == EM_ARM)
    return;

  /* GCC 6 and earlier did not support stack clash protection.  */
  if (gcc_version < 7)
    return;

  if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	fail (data, "Parts of the binary were compiled without stack clash protection");
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
	maybe (data, "The stack clash protections setting was not recorded");
    }
  else if (results->num_pass > 0)
    {
      pass (data, "Compiled with -fstack-clash-protection");
    }
  else
    {
      maybe (data, "The -fstack-clash-protection setting was not recorded");
    }
}

static void
show_FORTIFY (annocheck_data * data, test * results)
{
  if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	fail (data, "Parts of the binary were compiled without -D_FORTIFY_SOURCE=2");
      else
	fail (data, "The binary was compiled without -DFORTIFY_SOURCE=2");
    }
  else if (results->num_maybe > 0)
    {
      if (results->num_pass > 0)
	{
	  if (! BE_VERBOSE)
	    maybe (data, "Some parts of the binary do not record if -D_FORTIFY_SOURCE=2 was used.  Run with -v to see where");
	  else
	    maybe (data, "Some parts of the binary do not record if -D_FORTIFY_SOURCE=2 was used");
	}
      else
	maybe (data, "The -D_FORTIFY_SOURCE=2 option was not seen");
    }
  else if (results->num_pass > 0)
    {
      pass (data, "Compiled with -D_FORTIFY_SOURCE=2");
    }
  else
    {
      maybe (data, "The -D_FORTIFY_SOURCE=2 option was not seen");
    }
}

static void
show_CF_PROTECTION (annocheck_data * data, test * results)
{
  if (e_machine != EM_386 && e_machine != EM_X86_64)
    return;

  /* GCC 7 and earlier did not support stack clash protection.  */
  if (gcc_version < 8)
    return;

  if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	fail (data, "Parts of the binary were compiled without sufficient -fcf-protection");
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
    {
      pass (data, "Compiled with -fcf-protection");
    }
  else
    {
      maybe (data, "The -fcf-protection option was not seen");
    }
}

static void
show_GLIBCXX_ASSERTIONS (annocheck_data * data, test * results)
{
  if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	fail (data, "Parts of the binary were compiled without -D_GLIBCXX_ASSRTIONS");
      else
	fail (data, "The binary was compiled without -D_GLIBCXX_ASSERTIONS");
    }
  else if (results->num_maybe > 0)
    {
      if (results->num_pass > 0)
	{
	  if (! BE_VERBOSE)
	    maybe (data, "Some parts of the binary do not record whether -D_GLIBCXX_ASSERTIONS was used.  Run with -v to see where");
	  else
	    maybe (data, "Some parts of the binary do not record whether -D_GLIBCXX_ASSERTIONS was used");
	}
      else
	maybe (data, "The -D_GLIBCXX_ASSERTIONS option was not seen");
    }
  else if (results->num_pass > 0)
    {
      pass (data, "Compiled with -D_GLIBCXX_ASSERTIONS");
    }
  else
    {
      maybe (data, "The -D_GLIBCXX_ASSERTIONS option was not seen");
    }
}

static void
show_STACK_REALIGN (annocheck_data * data, test * results)
{
  if (e_machine != EM_386)
    return;

  if (results->num_fail > 0)
    {
      if (results->num_pass > 0 || results->num_maybe > 0)
	fail (data, "Parts of the binary were compiled without -mstack-realign");
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
    {
      pass (data, "Compiled with -mstack_realign");
    }
  else
    {
      maybe (data, "The -mstack-realign option was not seen");
    }
}

static bool
finish (annocheck_data * data)
{
  if (disabled || debuginfo_file)
    return true;

  if (! ignore_gaps && e_type != ET_REL)
    check_for_gaps (data);

  int i;
  for (i = 0; i < TEST_MAX; i++)
    {
      if (tests[i].enabled)
	{
	  tests[i].show_result (data, tests + i);
	  einfo (VERBOSE2, " Use --skip-%s to disable this test", tests[i].name);
	}
    }

  if (num_fails == num_maybes && num_fails == 0)
    {
      einfo (INFO, "%s: PASS", data->filename);
      return true;
    }
  else if (num_fails > 0)
    return false;
  else /* FIXME: Add an option to ignore MAYBE results ? */
    return false;
}

static void
version (void)
{
  einfo (INFO, "version 1.1");
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
  NULL, /* check_seg */
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
  if (! annocheck_add_checker (& hardened_checker, major_version))
    disabled = true;
}
