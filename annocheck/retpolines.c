/* Detects the presence of retpoline instruction sequences in a binary.
   Copyright (c) 2018 - 2019 Red Hat.

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

static bool disabled = false;
static bool detect_retpolines = true;
static bool detect_ibt_plt_stubs = false;
static bool found_retpolines = false;
static int  e_type;

static enum
{
  NOT_FOUND,
  FOUND,
  NEEDED
} found_ibt_plt_stubs;

static bool
start_file (annocheck_data * data)
{
  int  e_machine;

  if (detect_retpolines == false && detect_ibt_plt_stubs == false)
    disabled = true;

  if (disabled)
    return false;

  found_retpolines = false;
  found_ibt_plt_stubs = NOT_FOUND;

  if (data->is_32bit)
    {
      Elf32_Ehdr * hdr = elf32_getehdr (data->elf);

      e_type = hdr->e_type;
      e_machine = hdr->e_machine;
    }
  else
    {
      Elf64_Ehdr * hdr = elf64_getehdr (data->elf);

      e_type = hdr->e_type;
      e_machine = hdr->e_machine;
    }

  return (e_machine == EM_X86_64);
}

static bool
interesting_sec (annocheck_data *     data,
		 annocheck_section *  sec)
{
  if (disabled)
    return false;

  /* For retpolines we want to scan code sections.  */
  if (detect_retpolines
      && sec->shdr.sh_type == SHT_PROGBITS
      && sec->shdr.sh_flags & SHF_EXECINSTR
      && sec->shdr.sh_size > 0)
    return true;

  if (detect_ibt_plt_stubs)
    {
      /* For ibt stubs we want to scan the .plt section.  */
      if (streq (sec->secname, ".plt"))
	return true;

      /* We also want to check the GNU Property note.  */
      if (sec->shdr.sh_type == SHT_NOTE)
	return true;
    }

  /* We do not need any more information from the section,
     so there is no need to run the checker.  */
  return false;
}

static bool
walk_property_notes (annocheck_data *     data,
		     annocheck_section *  sec,
		     GElf_Nhdr *          note,
		     size_t               name_offset,
		     size_t               data_offset,
		     void *               ptr)
{
  if (note->n_type == NT_GNU_PROPERTY_TYPE_0
      && found_ibt_plt_stubs != FOUND
      && (e_type == ET_EXEC || e_type == ET_DYN))
    /* FIXME: We are assuming that if a property note is present then CET should be enabled.  */
    found_ibt_plt_stubs = NEEDED;

  return true;
}


static bool
check_sec (annocheck_data *     data,
	   annocheck_section *  sec)
{
  if (sec->data->d_size == 0)
    return true;

  if (detect_retpolines
      && ! found_retpolines
      && sec->shdr.sh_type == SHT_PROGBITS
      && sec->shdr.sh_flags & SHF_EXECINSTR
      && sec->shdr.sh_size > 0)
    {
      /* Look for the binary sequence:
	 f3 90                	pause  
	 0f ae e8             	lfence.  */
#define SEQ_LENGTH 5
      static char sequence[SEQ_LENGTH] = { 0xf3, 0x90, 0x0f, 0xae, 0xe8 };
      size_t i;

      einfo (VERBOSE2, "%s: check contents of %s section", data->filename, sec->secname);

      for (i = 0; i < sec->data->d_size - SEQ_LENGTH; i++)
	{
	  /* FIXME: There are faster ways of doing this...  */
	  if (memcmp (sec->data->d_buf + i, sequence, SEQ_LENGTH) == 0)
	    {
	      einfo (VERBOSE2, "%s: sequence found in section %s", data->filename, sec->secname);
	      found_retpolines = true;
	      break;
	    }
	}
    }

  if (detect_ibt_plt_stubs
      && found_ibt_plt_stubs == NOT_FOUND
      && streq (sec->secname, ".plt"))
    {
      const unsigned char * buf = sec->data->d_buf;

      einfo (VERBOSE, "%s: check contents of .plt section", data->filename);

      /* Look for the ENDBR64 insn in the sequence:
	 10:	f3 0f 1e fa          	endbr64 
	 14:	ff 35 8e 0f 20 00    	pushq  0x......(%rip)
	 1a:	ff 25 78 0f 20 00    	jmpq  *0x......(%rip).  */
      if (sec->data->d_size >= 0x20
	  && buf[0x10] == 0xf3
	  && buf[0x11] == 0x0f
	  && buf[0x12] == 0x1e
	  && buf[0x13] == 0xfa)
	found_ibt_plt_stubs = FOUND;
    }

  if (detect_ibt_plt_stubs
      && sec->shdr.sh_type == SHT_NOTE
      && streq (sec->secname, ".note.gnu.property"))
    {
      einfo (VERBOSE, "%s: scan GNU property notes", data->filename);
      return annocheck_walk_notes (data, sec, walk_property_notes, NULL);
    }
  
  return true;
}

static void
usage (void)
{
  einfo (INFO, "Detects the presence of specific code sequences in binary files");
  einfo (INFO, "  Use --[no-]detect-retpolines to enable detection of retpolines.  [default: enabled]");
  einfo (INFO, "  Use --[no-]detect-ibt-plt-stubs to enable detection of IBT enabled PLT stubs.  [default: disabled]");
}

static bool
process_arg (const char * arg, const char ** argv, const uint argc, uint * next_indx)
{
  if (streq (arg, "--detect-retpolines"))
    detect_retpolines = true;

  else if (streq (arg, "--no-detect-retpolines"))
    detect_retpolines = false;

  else if (streq (arg, "--detect-ibt-plt-stubs"))
    detect_ibt_plt_stubs = true;
  
  else if (streq (arg, "--no-detect-ibt-plt-stubs"))
    detect_ibt_plt_stubs = false;

  else
    return false;

  return true;
}

static void
version (void)
{
  einfo (INFO, "Version 1.1");
}

static bool
end_file (annocheck_data * data)
{
  if (disabled)
    return false;

  if (detect_retpolines)
    einfo (VERBOSE, "%s: %s", data->filename, found_retpolines ? "uses retpolines" : "does not use retpolines");

  if (detect_ibt_plt_stubs)
    {
      switch (found_ibt_plt_stubs)
	{
	case NOT_FOUND:
	  einfo (INFO, "%s: no IBT enabled stubs found (not needed)", data->filename);
	  break;
	case FOUND:
	  einfo (INFO, "%s: IBT enabled stubs found", data->filename);
	  break;
	case NEEDED:
	  einfo (INFO, "%s: no IBT enabled stubs found (but they are needed)", data->filename);
	  return false;
	  break;
	  
	}
    }

  return true;
}

struct checker retpoline_checker = 
{
  "Retpoline Detector",
  start_file,
  interesting_sec,
  check_sec, 
  NULL, /* interesting_seg */
  NULL, /* check_seg */
  end_file,
  process_arg, /* process_arg  */
  usage,
  version,
  NULL, /* start_scan */
  NULL, /* end_scan */
  NULL /* internal */
};

static __attribute__((constructor)) void
register_checker (void) 
{
  if (! annocheck_add_checker (& retpoline_checker, ANNOBIN_VERSION / 100))
    disabled = true;
}
