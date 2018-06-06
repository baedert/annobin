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

/* These are initialised on a per-input-file basis by start().  */
static bool i686_found;
static bool x86_found;
static bool arm_found;
static bool debuginfo_file;

static bool bind_now_found;
static bool dynamic_segment_found;
static bool gnu_relro_found;
static bool et_exec_found;
static bool gnu_stack_found;
static bool rwx_seg_found;
static bool textrel_found;
static bool bad_run_path_found;
static bool gap_detected;
static bool thread_cancellation;
static bool writable_got_relocations;
static int  stack_realign;
static int  pic_level;
static int  stack_protection;
static int  fortify_level;
static int  final_fortify_level;
static int  optimization_level;
static int  glibcxx_assertions;
static int  stack_clash_protection;
static int  cf_protection;
static int  num_fails;
static int  num_maybes;
static int  gcc_version;

#define UNKNOWN -1
#define YES      1
#define NO       0
#define BOTH    -2

static void
start (eu_checksec_data * data)
{
  debuginfo_file = false;
  bind_now_found = false;
  dynamic_segment_found = false;
  gnu_relro_found = false;
  gnu_stack_found = false;
  rwx_seg_found = false;
  textrel_found = false;
  bad_run_path_found = false;
  gap_detected = false;
  thread_cancellation = true;
  writable_got_relocations = false;

  pic_level = UNKNOWN;
  cf_protection = UNKNOWN;
  stack_clash_protection = UNKNOWN;
  stack_protection = UNKNOWN;
  final_fortify_level = fortify_level = UNKNOWN;
  optimization_level = UNKNOWN;
  glibcxx_assertions = UNKNOWN;
  stack_realign = UNKNOWN;
  gcc_version = UNKNOWN;

  num_fails = 0;
  num_maybes = 0;

  if (data->is_32bit)
    {
      Elf32_Ehdr * hdr = elf32_getehdr (data->elf);

      et_exec_found = hdr->e_type == ET_EXEC;
      x86_found     = hdr->e_machine == EM_386;
      i686_found    = x86_found;
      arm_found     = hdr->e_machine == EM_ARM;
    }
  else
    {
      Elf64_Ehdr * hdr = elf64_getehdr (data->elf);
      
      et_exec_found = hdr->e_type == ET_EXEC;
      x86_found     = hdr->e_machine == EM_X86_64;
      i686_found    = false;
      arm_found     = false;
    }
}

static bool
interesting_sec (eu_checksec_data *     data,
		 eu_checksec_section *  sec)
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
    if ((sec->shdr.sh_flags & (SHF_WRITE | SHF_EXECINSTR)) == SHF_WRITE)
      gnu_stack_found = true;

  /* Note the permissions on GOT/PLT relocation sections.  */
  if (streq  (sec->secname, ".rel.got")
      || streq  (sec->secname, ".rela.got")
      || streq  (sec->secname, ".rel.plt")
      || streq  (sec->secname, ".rela.plt"))
    {
      if (sec->shdr.sh_flags & SHF_WRITE)
	writable_got_relocations = true;
    }

  return sec->shdr.sh_type == SHT_DYNAMIC
    || sec->shdr.sh_type == SHT_NOTE
    || sec->shdr.sh_type == SHT_STRTAB;
}

static inline unsigned long
align (unsigned long val, unsigned long alignment)
{
  return (val + (alignment - 1)) & (~ (alignment - 1));
}

typedef struct hardened_note_data
{
  ulong         prev_end;
  ulong         start;
  ulong         end;
} hardened_note_data;

static const char *
get_component_name (eu_checksec_data *     data,
		    eu_checksec_section *  sec,
		    hardened_note_data *   note_data,
		    bool                   inc_addr,
		    bool                   prefer_func_symbol)
{
  static char buffer[256];
  const char * sym = eu_checksec_find_symbol_for_address_range (data, sec, note_data->start, note_data->end, prefer_func_symbol);

  if (sym == NULL || inc_addr)
    sprintf (buffer, "addr range: %#lx..%#lx ", note_data->start, note_data->end);
  else
    buffer[0] = 0;

  if (sym)
    {
      strcat (buffer, "component: ");
      strcat (buffer, sym);
    }

  return buffer;
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
walk_notes (eu_checksec_data *     data,
	    eu_checksec_section *  sec,
	    GElf_Nhdr *            note,
	    size_t                 name_offset,
	    size_t                 data_offset,
	    void *                 ptr)
{
  bool prefer_func_name;
  hardened_note_data * note_data;

  if (note->n_type != NT_GNU_BUILD_ATTRIBUTE_OPEN
      && note->n_type != NT_GNU_BUILD_ATTRIBUTE_FUNC)
    return true;

  prefer_func_name = note->n_type == NT_GNU_BUILD_ATTRIBUTE_FUNC;
  note_data = (hardened_note_data *) ptr;

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

	  for (shift = i = 0; i < 8; i++)
	    {
	      ulong byte;

	      byte = descdata[i];
	      start |= byte << shift;

	      byte = descdata[i + 8];
	      end |= byte << shift;

	      shift += 8;
	    }
	}
      else if (note->n_descsz == 8)
	{
	  start = descdata[0] | (descdata[1] << 8) | (descdata[2] << 16) | (descdata[3] << 24);
	  end   = descdata[4] | (descdata[5] << 8) | (descdata[6] << 16) | (descdata[7] << 24);
	}
      else
	return false;

      if (note->n_type == NT_GNU_BUILD_ATTRIBUTE_OPEN)
	{
	  if (note_data->prev_end > 0
	      && start > align (note_data->prev_end, 16))
	    {
	      hardened_note_data fake_note;

	      fake_note.start = note_data->prev_end + 1;
	      fake_note.end   = start;
	      
	      /* Note - we ignore gaps at the start and end of the file.  These are
		 going to be from the crt code which does not need to be chacked.  */
	      einfo (VERBOSE, "%s: GAP:  (%s) in annobin notes",
		     data->filename, get_component_name (data, sec, & fake_note, true, prefer_func_name));
	      gap_detected = true;
	    }

	  note_data->prev_end = end;
	}

      note_data->start = start;
      note_data->end   = end;
    }

  if (note->n_namesz < 3)
    return false;

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
  uint          value = UNKNOWN;

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
      if (value != UNKNOWN)
	einfo (VERBOSE, "ICE: The tool note should have a string attribute");
      else
	{
	  /* Parse the tool attribute looking for the version of gcc used to build the component.  */
	  const char * gcc = strstr (attr, "gcc");
	  if (gcc)
	    {
	      /* FIXME: This assumes that the tool string looks like: "gcc 7.x.x......"  */
	      unsigned long version = strtoul (gcc + 4, NULL, 10);

	      einfo (VERBOSE2, "%s: (%s) built-by gcc version %lu",
		     data->filename,
		     get_component_name (data, sec, note_data, false, prefer_func_name),
		     version);

	      if (gcc_version == UNKNOWN)
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
      if (value == UNKNOWN)
	return false;
      if (pic_level == UNKNOWN)
	pic_level = value;
      else if (pic_level != value)
	{
	  einfo (VERBOSE, "%s: mayb: (%s): Compiled with a different -fPIC/-fPIE setting",
		 data->filename, get_component_name (data, sec, note_data, false, prefer_func_name));
	  /* Remember the lowest PIC level.  */
	  pic_level = value < pic_level ? value : pic_level;
	}
      break;

    case GNU_BUILD_ATTRIBUTE_STACK_PROT:
      if (value == UNKNOWN)
	return false;

      /* We know that __libc_csu_init cannot be compiled with stack protection
	 enabled because it is part of glibc's start up code.  So do not complain.  */
      if (value == 0
	  && streq (get_component_name (data, sec, note_data, false, false), "__libc_csu_init"))
	break;
      
      switch (value)
	{
	case 0: /* NONE */
	  einfo (VERBOSE, "%s: fail: (%s): No stack protection enabled",
		 data->filename, get_component_name (data, sec, note_data, false, prefer_func_name));
	  break;
	case 1: /* BASIC (funcs using alloca or with local buffers > 8 bytes) */
	case 4: /* EXPLICIT */
	  einfo (VERBOSE, "%s: fail: (%s): Insufficient stack protection: %s",
		 data->filename, get_component_name (data, sec, note_data, false, prefer_func_name),
		 stack_prot_type (value));
	  break;
	case 2: /* ALL */
	case 3: /* STRONG */
	  break;
	default:
	  einfo (VERBOSE, "ICE: Unexpected stack protection level of %d", value);
	  return false;
	}

      if (stack_protection == UNKNOWN)
	stack_protection = value;
      else if (stack_protection == BOTH)
	;
      else if (stack_protection != value)
	{
	  if ((value == 2 && stack_protection == 3)
	      || (value == 3 && stack_protection == 2))
	    ;
	  else
	    /* No need for a warning - the switch above will have handled that.  */
	    stack_protection = BOTH;
	}
      break;

    case 'c':
      if (streq (attr, "cf_protection"))
	{
	  if (value == UNKNOWN)
	    return false;

	  switch (value)
	    {
	    default:
	      einfo (INFO, "%s: ICE:  Unexpected value for cf-protection: %d", data->filename, value);
	      break;
	    case 4:
	    case 8:
	      if (cf_protection != BOTH)
		cf_protection = YES;
	      break;
	    case 2:
	    case 6:
	      if (x86_found)
		einfo (VERBOSE, "%s: fail: (%s): Only compiled with -fcf-protection=branch",
		       data->filename, get_component_name (data, sec, note_data, false, prefer_func_name));
	      cf_protection = BOTH;
	      break;
	    case 3:
	    case 7:
	      if (x86_found)
		einfo (VERBOSE, "%s: fail: (%s): Only compiled with -fcf-protection=return",
		       data->filename, get_component_name (data, sec, note_data, false, prefer_func_name));
	      cf_protection = BOTH;
	      break;
	    case 5:
	    case 1:
	      if (x86_found)
		einfo (VERBOSE, "%s: fail: (%s): Compiled without -fcf-protection",
		       data->filename, get_component_name (data, sec, note_data, false, prefer_func_name));
	      cf_protection = BOTH;
	      break;
	    }
	}

    case 'F':
      if (streq (attr, "FORTIFY"))
	{
	  if (value == UNKNOWN)
	    return false;
	  else if (fortify_level == UNKNOWN)
	    final_fortify_level = fortify_level = value;
	  else if (fortify_level != value)
	    {
	      /* A change in the FORTIFY level has been detected!  */
	      switch (fortify_level)
		{
		case 0:
		case 2:
		  einfo (VERBOSE, "%s: fail: (%s): Change in _FORTIFY_SOURCE level from %d to %d",
			 data->filename, 
			 get_component_name (data, sec, note_data, false, prefer_func_name),
			 fortify_level, value);
		  break;
		default:
		  einfo (VERBOSE, "ICE: Unexpected FORTIFY level of %d", fortify_level);
		  break;
		}

	      fortify_level = value;
	      final_fortify_level = BOTH;
	    }
	}
      break;

    case 'G':
      if (streq (attr, "GOW"))
	{
	  if (value == UNKNOWN)
	    return false;

	  value = (value >> 9) & 3;

	  if (optimization_level == UNKNOWN)
	    optimization_level = value;

	  if (value == 0 || value == 1)
	    {
	      einfo (VERBOSE, "%s: fail: (%s): Insufficient optimization level: -O%d",
		     data->filename, 
		     get_component_name (data, sec, note_data, false, prefer_func_name),
		     value);
	      optimization_level = value;
	    }
	}
      else if (streq (attr, "GLIBCXX_ASSERTIONS"))
	{
	  switch (value)
	    {
	    case 0:
	      einfo (VERBOSE, "%s: fail: (%s): Compiled without -D_GLIBCXX_ASSERTIONS",
		     data->filename, get_component_name (data, sec, note_data, false, prefer_func_name));
	      if (glibcxx_assertions == UNKNOWN)
		glibcxx_assertions = NO;
	      else if (glibcxx_assertions == YES)
		glibcxx_assertions = BOTH;
	      break;
	    case 1:
	      if (glibcxx_assertions == UNKNOWN)
		glibcxx_assertions = YES;
	      break;
	    default:
	      einfo (VERBOSE, "ICE: Unexpected GLIBCXX_ASSERTIONS value: %d", value);
	      return false;
	    }
	}
      break;

    case 's':
      if (streq (attr, "stack_clash"))
	{
	  switch (value)
	    {
	    case 0:
	      if (! arm_found)
		einfo (VERBOSE, "%s: fail: (%s): Compiled without -fstack-clash-protection",
		       data->filename, get_component_name (data, sec, note_data, false, prefer_func_name));
	      stack_clash_protection = NO;
	      break;
	    case 1:
	      if (stack_clash_protection == UNKNOWN)
		stack_clash_protection = YES;
	      break;
	    default:
	      if (! arm_found)
		einfo (VERBOSE, "ICE: Unexpected stack-clash value: %d", value);
	      return false;
	    }
	}
      else if (streq (attr, "stack_realign"))
	{
	  if (stack_realign == UNKNOWN)
	    stack_realign = value;
	  else if (stack_realign != value)
	    {
	      if (value == NO)
		einfo (VERBOSE, "%s: fail: (%s): Stack realignment not enabled",
		       data->filename, get_component_name (data, sec, note_data, false, prefer_func_name));
	      stack_realign = BOTH;
	    }
	}
      break;
      
    default:
      break;
    }

  return true;
}

static bool
check_note_section (eu_checksec_data *    data,
		    eu_checksec_section * sec)
{
  if (streq (sec->secname, GNU_BUILD_ATTRS_SECTION_NAME))
    {
      hardened_note_data hard_data;

      hard_data.start = 0;
      hard_data.end = 0;
      hard_data.prev_end = 0;

      return eu_checksec_walk_notes (data, sec, walk_notes, (void *) & hard_data);
    }

  return true;
}

static bool
check_string_section (eu_checksec_data *    data,
		      eu_checksec_section * sec)
{
  /* Check the string table to see if it contains "__pthread_register_cancel".
     This is not as accurate as checking for a function symbol with this name,
     but it is a lot faster.  */
  if (strstr ((const char *) sec->data->d_buf, "__pthread_register_cancel"))
    thread_cancellation = NO;

  return true;
}

/* Returns TRUE iff STR contains a search path that does not start with /usr.  */

static bool
not_rooted_at_usr (const char * str)
{
  while (str)
    {
      if (! const_strneq (str, "/usr"))
	return true;
      str = strchr (str, ':');
      if (str)
	str++;
    }
  return false;
}

static bool
check_dynamic_section (eu_checksec_data *    data,
		       eu_checksec_section * sec)
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
	bind_now_found = true;

      if (dyn->d_tag == DT_FLAGS)
	{
	  if (dyn->d_un.d_val & DF_BIND_NOW)
	    bind_now_found = true;
	}

      if (dyn->d_tag == DT_TEXTREL)
	textrel_found = true;

      if (dyn->d_tag == DT_RPATH || dyn->d_tag == DT_RUNPATH)
	if (not_rooted_at_usr (elf_strptr (data->elf, sec->shdr.sh_link, dyn->d_un.d_val)))
	  bad_run_path_found = true;
    }

  return true;
}  

static bool
check_sec (eu_checksec_data *     data,
	   eu_checksec_section *  sec)
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
interesting_seg (eu_checksec_data *    data,
		 eu_checksec_segment * seg)
{
  if (disabled)
    return false;

  switch (seg->phdr->p_type)
    {
    case PT_GNU_RELRO:
      gnu_relro_found = true;
      break;

    case PT_GNU_STACK:
      gnu_stack_found = true;
      break;

    case PT_DYNAMIC:
      dynamic_segment_found = true;
      break;

    default:
      break;
    }

  if ((seg->phdr->p_flags & (PF_X | PF_W | PF_R)) == (PF_X | PF_W | PF_R))
    {
      einfo (VERBOSE, "%s: fail: seg %d has Read, Write and eXecute flags\n",
	     data->filename, seg->number);
      rwx_seg_found = true;
    }

  return false;
}

static void
fail (eu_checksec_data * data, const char * message)
{
  einfo (INFO, "%s: FAIL: %s", data->filename, message);
  ++ num_fails;
}

static void
maybe (eu_checksec_data * data, const char * message)
{
  einfo (INFO, "%s: MAYB: %s", data->filename, message);
  ++ num_maybes;
}

static void
pass (eu_checksec_data * data, const char * message)
{
  einfo (VERBOSE, "%s: pass: %s", data->filename, message);
}

static void
ice (eu_checksec_data * data, const char * message)
{
  einfo (INFO, "%s: internal error: %s", data->filename, message);
}

static bool
finish (eu_checksec_data * data)
{
  if (disabled || debuginfo_file)
    return true;

  if (gap_detected)
    {
      if (! BE_VERBOSE)
	maybe (data, "Gaps were detected in the annobin coverage.  Run with -v to list");
      else
	maybe (data, "Gaps were detected in the annobin coverage");
    }

  if (bind_now_found)
    pass (data, "Linked with -Wl,-z,now");
  else
    fail (data, "Not linked with -Wl,-z,now");

  if (dynamic_segment_found)
    pass (data, "Dynamic segment is present");
  else
    maybe (data, "Dynamic segment is absent");

  if (writable_got_relocations)
    fail (data, "Relocations for the GOT/PLT sections are writeable");
  else
    pass (data, "GOT/PLT relocations are read only");

  if (gnu_relro_found)
    pass (data, "Linked with -Wl,-z,relro");
  else
    fail (data, "Not linked with -Wl,-z,relro");

  if (gnu_stack_found)
    pass (data, "Stack not executable");
  else
    fail (data, "Executable stack found ?");

  if (rwx_seg_found)
    fail (data, "RWX segment found");
  else
    pass (data, "No RWX segments found");

  if (textrel_found)
    fail (data, "Text relocations found");
  else
    pass (data, "No text relocations found");

  if (bad_run_path_found)
    fail (data, "DT_RPATH/DT_RUNPATH contains directories not starting with /usr");
  else
    pass (data, "DT_RPATH/DT_RUNPATH absent or rooted at /usr");

  if (thread_cancellation)
    pass (data, "No thread cancellation problems");
  else
    fail (data, "Thread cancellation not hardened.  (Compiled without -fexceptions)");

  /* Check PIC/PIE.  */
  switch (pic_level)
    {
    case UNKNOWN:
      maybe (data, "PIC/PIE setting not recorded");
      break;
    case 0:
      fail (data, "Compiled without any PIC option");
      break;
    case 1:
    case 2:
      if (et_exec_found)
	fail (data, "Compiled with PIC rather than PIE");
      else
	pass (data, "Compiled with PIC");
      break;
    case 3:
    case 4:
      pass (data, "Compiled with PIE");
      break;
    default:
      ice (data, "Unknown PIC level");
      break;
    }

  switch (stack_protection)
    {
    case BOTH:
      if (! BE_VERBOSE)
	fail (data, "Conflicting stack protection settings.  Run with -v to list");
      else
	fail (data, "Conflicting stack protection settings.");
      break;
    case UNKNOWN:
      fail (data, "Stack protection status is not recorded");
      break;
    case 2:
    case 3:
      pass (data, "Strong stack protection is enabled");
      break;
    case NO: 
      fail (data, "Stack protection has not been enabled");
      break;
    case 1:
    case 4:
      fail (data, "Stack protection is not strong enough");
      break;
    default:
      maybe (data, "stack protection has an unknown value");
      break;
    }

  if (! arm_found)
    {
      switch (stack_clash_protection)
	{
	case UNKNOWN:
	  if (gcc_version >= 7)
	    maybe (data, "-fstack-clash-protection not recorded");
	  break;
	case NO:
	  fail (data, "-fstack-clash-protection not used");
	  break;
	case YES:
	  pass (data, "Compiled with -fstack-clash-protection");
	  break;
	default:
	  ice (data, "stack-clash notes are incorrect");
	  break;
	}
    }

  switch (final_fortify_level)
    {
    case BOTH:
      if (! BE_VERBOSE)
	fail (data, "Conflicting -D_FORTIFY_SOURCE levels.  Run with -v to list");
      else
	fail (data, "Conflicting -D_FORTIFY_SOURCE levels");
      break;
    case UNKNOWN:
      fail (data, "-D_FORTIFY_SOURCE level not recorded");
      break;
    case 2:
      pass (data, "-D_FORTIFY_SOURCE=2 specified");
      break;
    case 0:
    case 1:
      fail (data, "-D_FORTIFY_SOURCE level too small");
      break;
    default:
      maybe (data, "-D_FORTIFY_SOURCE level unexpectedly large");
      break;
    }

  switch (optimization_level)
    {
    case UNKNOWN:
      fail (data, "Optimization level not recorded");
      break;
    case 3:
    case 2:
      pass (data, "Sufficient compiler optimization used");
      break;
    case 0:
    case 1:
      fail (data, "Insufficient compiler optimization");
      break;
    default:
      maybe (data, "Optimization level unexpectedly large");
      break;
    }

  switch (glibcxx_assertions)
    {
    case BOTH:
      if (! BE_VERBOSE)
	fail (data, "Some components not compiled with -D_GLIBCXX_ASSERTONS.  Run with -v to list");
      else
	fail (data, "Some components not compiled with -D_GLIBCXX_ASSERTONS");
      break;
    case UNKNOWN:
      maybe (data, "-D_GLIBCXX_ASSERTIONS not recorded");
      break;
    case NO:
      fail (data, "-D_GLIBCXX_ASSERTIONS not used");
      break;
    case YES:
      pass (data, "Compiled with -D_GLIBCXX_ASSERTIONS");
      break;
    default:
      ice (data, "glibcxx_assertion notes incorrect");
      break;
    }  

  if (x86_found)
    {
      switch (cf_protection)
	{
	case UNKNOWN:
	  if (gcc_version >= 8)
	    maybe (data, "-fcf-protection not recorded");
	  break;
	case BOTH:
	  if (! BE_VERBOSE)
	    fail (data, "Some components compiled without -fcf-protection.  Run with -v to list");
	  else
	    fail (data, "Some components compiled without -fcf-protection");
	  break;
	case NO:
	  fail (data, "-fcf-protection not enabled");
	  break;      
	case YES:
	  pass (data, "Compiled with -fcf-protection=full");
	  break;
	default:
	  ice (data, "cf_protection notes are incorrect");
	  break;
	}
    }

  if (i686_found)
    {
      switch (stack_realign)
	{
	case UNKNOWN:
	  maybe (data, "-mstackrealign not recorded");
	  break;
	case BOTH:
	  if (! BE_VERBOSE)
	    fail (data, "-mstackrealign only partially used.  Run with -v to list");
	  else
	    fail (data, "-mstackrealign only partially used.");
	  break;
	case NO:
	  fail (data, "Compiled without -mstackrealign");
	  break;
	case YES:
	  pass (data, "Compiled wit -mstackrealign");
	  break;
	default:
	  ice (data, "-mstackrealign notes are incorrect");
	  break;
	}
    }

  if (num_fails == num_maybes && num_fails == 0)
    {
      einfo (INFO, "%s: PASS", data->filename);
      return true;
    }
  else if (num_fails > 0)
    return false;
  else /* FIXME: Add an option to ignore MAYBE results... */
    return false;
}

static void
version (void)
{
  einfo (INFO, "version 1.0");
}

static void
usage (void)
{
  einfo (INFO, "Hardening/Security checker.  Tests for:");
  einfo (INFO, "  lazy binding");
  einfo (INFO, "  executable stack");
  einfo (INFO, "  segments with write + executable");
  einfo (INFO, "  text relocations");
  einfo (INFO, "  runpath entries not under /usr");
  einfo (INFO, "  missing annobin data");
  einfo (INFO, "  missing dynamic segment");
  einfo (INFO, "  writeable relocations for the GOT");
  einfo (INFO, "  compilation without sufficient optimization");
  einfo (INFO, "  compilation without -fstack-protector-strong");
  einfo (INFO, "  compilation without -D_FORTIFY_SOURCE=2");
  einfo (INFO, "  compilation without -D_GLIBCXX_ASSERTIONS");
  einfo (INFO, "  compilation without -fPIE");
  einfo (INFO, "  compilation without -fstack-clash-protection (not arm)");
  einfo (INFO, "  compilation without -fexceptions");
  einfo (INFO, "  compilation without -fcf-protection=full (x86 only, gcc 8 only)");
  einfo (INFO, "  compilation without -mstackrealign (i686 only)");
  einfo (INFO, "Still to do:");
  einfo (INFO, "  Add a machine readable output mode");
  einfo (INFO, "This tool is enabled by default.  This can be changed by:");
  einfo (INFO, "  --disable-hardened  Disables the hardening checker");
  einfo (INFO, "  --enable-hardened   Reenables the hardening checker");  
}

static bool
process_arg (const char * arg, const char ** argv, const uint argc, uint * next)
{
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
  NULL, /* internal */
};

static __attribute__((constructor)) void
register_checker (void) 
{
  if (! eu_checksec_add_checker (& hardened_checker, major_version))
    disabled = true;
}
