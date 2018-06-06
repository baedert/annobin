/* annocheck - A tool for checking security features of binares.
   Copyright (c) 2018 Red Hat.
   Created by Nick Clifton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "annocheck.h"
#include <rpm/rpmlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <elfutils/libdwelf.h>
#include <elfutils/libdwfl.h>

/* Maximum number of input files.  FIXME: Use a linked list instead.  */
#define MAX_NUM_FILES 256

/* -1: silent, 0: normal, 1: verbose, 2: very verbose.  */
ulong         verbosity = 0;

uint          major_version = 1;
uint          minor_version = 0;

static ulong         	num_files = 0;
static const char *     files[MAX_NUM_FILES];
static const char *     progname;
static const char *	base_component = "annocheck";
static const char *	component = "annocheck";
static bool             ignore_unknown = false;
static char *           saved_args = NULL;
static char *           prefix = "";
static const char *     dwarf_path = NULL;

static checker *        first_checker = NULL;
static checker *        first_sec_checker = NULL;
static checker *        first_seg_checker = NULL;

typedef struct checker_internal
{
  /* Pointer to the next section checker.  */
  struct checker * next_sec;

  /* Pointer to the next segment checker.  */
  struct checker * next_seg;

  /* Pointer to the next checker.  */
  struct checker * next;

} checker_internal;
  
/* -------------------------------------------------------------------- */
/* Print a message on stdout or stderr.  Returns FALSE (for error
   messages) so that it can be used as a terminator in boolean functions.  */

bool
einfo (einfo_type type, const char * format, ...)
{
  FILE *        file;
  const char *  do_newline = "";
  const char *  pref = NULL;
  va_list       args;
  bool          res = false;

  switch (type)
    {
    case WARN:
    case SYS_WARN:
      pref = "Warning";
      file   = stderr;
      break;
    case ERROR:
    case SYS_ERROR:
      pref = "Error";
      file   = stderr;
      break;
    case FAIL:
      pref = "Internal Failure";
      file   = stderr;
      break;
    case VERBOSE2:
    case VERBOSE:
      //pref = "Verbose";
      file   = stdout;
      res    = true;
      break;
    case INFO:
      //pref = "Info";
      file   = stdout;
      res    = true;
      break;
    case PARTIAL:
      // pref = "";
      file   = stdout;
      res    = true;
      break;
    default:
      fprintf (stderr, "ICE: Unknown einfo type %x\n", type);
      exit (-1);
    }
  
  if (verbosity == -1UL
      || (type == VERBOSE && verbosity < 1)
      || (type == VERBOSE2 && verbosity < 2))
    return res;

  fflush (stderr);
  fflush (stdout);

  if (type != PARTIAL)
    fprintf (file, "%s: ", component);

  if (format[strlen (format) - 1] != '\n')
    do_newline = ".\n";

  if (pref)
    fprintf (file, "%s: ", pref);

  if (prefix[0])
    fprintf (file, "%s ", prefix);

  va_start (args, format);
  vfprintf (file, format, args);
  va_end (args);

  if (type == SYS_WARN || type == SYS_ERROR)
    fprintf (file, ": system error: %s", strerror (errno));

  if (type != PARTIAL)
    fprintf (file, "%s", do_newline);
  return res;
}

/* -------------------------------------------------------------------- */

static void
push_component (checker * checker)
{
  component = checker->name;
}

static void
pop_component (void)
{
  component = base_component;
}

/* -------------------------------------------------------------------- */

static void
add_file (const char * filename)
{
  if (num_files == MAX_NUM_FILES)
    return;

  files[num_files ++] = filename;
}

static void
print_version (void)
{
  einfo (INFO, "Version %d.%d", major_version, minor_version);

  checker * checker;
  for (checker = first_checker; checker != NULL; checker = ((checker_internal *)(checker->internal))->next)
    if (checker->version)
      {
	push_component (checker);
	checker->version ();
	pop_component ();
      }
}

static void
usage (void)
{
  einfo (INFO, "Runs various scans on the given files");
  einfo (INFO, "Useage: %s [options] <file(s)>", component);
  einfo (INFO, " Options are:");
  einfo (INFO, "   --dwarf-dir=<DIR>  [Look in <DIR> for separate dwarf debug information files]");
  einfo (INFO, "   --help             [Display this message & exit]");
  einfo (INFO, "   --ignore-unknown   [Do not complain about unknown file types]");
  einfo (INFO, "   --prefix=<TEXT>    [Include <TEXT> in the output description]");
  einfo (INFO, "   --quiet            [Do not print anything, just return an exit status]");
  einfo (INFO, "   --verbose          [Produce informational messages whilst working.  Repeat for more information]");
  einfo (INFO, "   --version          [Report the verion of the tool & exit]");

  einfo (INFO, "The following scanning tools are available:");
  checker * checker;
  for (checker = first_checker; checker != NULL; checker = ((checker_internal *)(checker->internal))->next)
    {
      push_component (checker);
      if (checker->usage)
	checker->usage ();
      else
	einfo (INFO, "Does not have any specific options");
      pop_component ();
    }
}

static void
save_arg (const char * arg)
{
  if (saved_args)
    {
      char * new_saved_args = concat (saved_args, " ", arg, NULL);
      free (saved_args);
      saved_args = new_saved_args;
    }
  else
    saved_args = concat (arg, NULL);
}

/* Handle command line options.  Returns to caller if there is
   something to do.  */

static bool
process_command_line (uint argc, const char * argv[])
{
  uint a = 1;

  progname = argv[0];

  while (a < argc)
    {
      const char * arg = argv[a];
      bool used = false;
      checker * checker;
      const char * parameter;

      ++ a;

      for (checker = first_checker; checker != NULL; checker = ((checker_internal *)(checker->internal))->next)
	if (checker->process_arg != NULL)
	  {
	    push_component (checker);
	    if (checker->process_arg (arg, argv, argc, & a))
	      used = true;
	    pop_component ();
	  }

      if (used)
	{
	  save_arg (arg);
	  continue;
	}

      if (arg[0] == '-')
        {
	  const char * orig_arg = arg;

	  arg += (arg[1] == '-' ? 2 : 1);
	  switch (*arg)
	    {
	    case 'h':
	      usage ();
	      exit (EXIT_SUCCESS);

	    case 'i':
	      ignore_unknown = true;
	      break;

	    case 'q':
	      save_arg (orig_arg);
	      verbosity = -1UL;
	      break;

	    case 'd':
	      save_arg (orig_arg);
	      parameter = strchr (arg, '=');
	      if (parameter == NULL)
		parameter = argv[a++];
	      else
		parameter ++;
	      dwarf_path = parameter;
	      break;

	    case 'p':
	      save_arg (orig_arg);
	      parameter = strchr (arg, '=');
	      if (parameter == NULL)
		parameter = argv[a++];
	      else
		parameter ++;
	      /* Prefix arguments accumulate.  */
	      prefix = concat (prefix, parameter, NULL);
	      break;

	    case 'v':
	      if (const_strneq (arg, "version"))
		{
		  print_version ();
		  exit (EXIT_SUCCESS);
		}
	      else if (const_strneq (arg, "verbose")
		       /* Allow -v as an alias for --verbose.  */
		       || arg[1] == 0)
		{
		  save_arg (orig_arg);
		  verbosity ++;
		}
	      else
		goto unknown_arg;
	      break;

	    default:
	    unknown_arg:
	      einfo (WARN, "Unrecognised command line option: %s ", orig_arg);
	      usage ();
	      return false;
	    }
	}
      else
	add_file (arg);
    }

  if (num_files == 0)
    {
      einfo (WARN, "No input files specified");
      usage ();
      return false;
    }

  return true;
}

/* -------------------------------------------------------------------- */

/* Utility function to walk over a note section calling FUNC
   on each note.  PTR is passed to FUNC along with a pointer to the note.
   If FUNC returns false the walk is terminated.
   Returns FALSE if the walk could not be executed.  */

bool
eu_checksec_walk_notes (eu_checksec_data * data, eu_checksec_section * sec, note_walker func, void * ptr)
{
  assert (data != NULL && sec != NULL && func != NULL);

  if (sec->shdr.sh_type != SHT_NOTE
      || sec->data == NULL
      || sec->data->d_size == 0)
    return false;

  size_t offset = 0;

  GElf_Nhdr  note;
  size_t     name_offset;
  size_t     data_offset;
  
  while ((offset = gelf_getnote (sec->data, offset, & note, & name_offset, & data_offset)) != 0)
    if (! func (data, sec, & note, name_offset, data_offset, ptr))
      break;

  return true;
}

/* Read in the section header for SECTION.  */

static void
read_section_header (eu_checksec_data * data, Elf_Scn * section, Elf64_Shdr * s64hdr)
{
  if (data->is_32bit)
    {
      Elf32_Shdr * shdr = elf32_getshdr (section);

      s64hdr->sh_name = shdr->sh_name;
      s64hdr->sh_type = shdr->sh_type;
      s64hdr->sh_flags = shdr->sh_flags;
      s64hdr->sh_addr = shdr->sh_addr;
      s64hdr->sh_offset = shdr->sh_offset;
      s64hdr->sh_size = shdr->sh_size;
      s64hdr->sh_link = shdr->sh_link;
      s64hdr->sh_info = shdr->sh_info;
      s64hdr->sh_addralign = shdr->sh_addralign;
      s64hdr->sh_entsize = shdr->sh_entsize;
    }
  else
    memcpy (s64hdr, elf64_getshdr (section), sizeof * s64hdr);
}
  
/* -------------------------------------------------------------------- */

static bool
run_checkers (const char * filename, int fd, Elf * elf)
{
  eu_checksec_data data;

  memset (& data, 0, sizeof data);
  data.full_filename = filename;
  data.filename = BE_VERBOSE ? filename : lbasename (filename);
  data.fd = fd;
  data.elf = elf;
  data.is_32bit = gelf_getclass (elf) == ELFCLASS32;

  checker * checker;

  /* Call the checker start functions.  */
  for (checker = first_checker; checker != NULL; checker = ((checker_internal *)(checker->internal))->next)
    if (checker->start)
      {
	push_component (checker);
	checker->start (& data);
	pop_component ();
      }

  bool ret = true;  

  if (first_sec_checker != NULL)
    {
      size_t shstrndx;

      if (elf_getshdrstrndx (elf, & shstrndx) < 0)
	return einfo (ERROR, "%s: Unable to locate string section", filename);
	      
      Elf_Scn * scn = NULL;

      while ((scn = elf_nextscn (elf, scn)) != NULL)
	{
	  eu_checksec_section  sec;

	  memset (& sec, 0, sizeof sec);

	  sec.scn = scn;
	  read_section_header (& data, scn, & sec.shdr);
	  sec.secname = elf_strptr (elf, shstrndx, sec.shdr.sh_name);	  

	  if (sec.shdr.sh_size == 0)
	    {
	      einfo (VERBOSE2, "%s: Skipping empty section: %s", filename, sec.secname);
	      continue;
	    }

	  einfo (VERBOSE2, "%s: Examining section %s", filename, sec.secname);

	  /* Walk the checkers, asking each in turn if they are interested in this section.  */
	  for (checker = first_sec_checker; checker != NULL; checker = ((checker_internal *)(checker->internal))->next_sec)
	    {
	      if (checker->interesting_sec == NULL)
		continue;

	      push_component (checker);

	      if (checker->interesting_sec (& data, & sec))
		{
		  /* Delay loading the section contents until a checker expresses interest.  */
		  if (sec.data == NULL)
		    {
		      sec.data = elf_getdata (scn, NULL);
		      if (sec.data == NULL)
			ret = einfo (ERROR, "Failed to read in section %s", sec.secname);
		    }

		  if (sec.data != NULL)
		    {
		      einfo (VERBOSE2, "is interested in section %s", sec.secname);

		      ret &= checker->check_sec (& data, & sec);
		    }
		}
	      else
		einfo (VERBOSE2, "is not interested in %s", sec.secname);

	      pop_component ();
	    }
	}
    }

  if (first_seg_checker != NULL)
    {
      size_t phnum;

      elf_getphdrnum (elf, & phnum);

      for (size_t cnt = 0; cnt < phnum; ++cnt)
	{
	  GElf_Phdr   mem;
	  eu_checksec_segment seg;

	  memset (& seg, 0, sizeof seg);

	  seg.phdr = gelf_getphdr (elf, cnt, & mem);
	  seg.number = cnt;

	  einfo (VERBOSE2, "%s: considering segment %lu", filename, cnt);

	  for (checker = first_seg_checker; checker != NULL; checker = ((checker_internal *)(checker->internal))->next_seg)
	    {
	      if (checker->interesting_seg == NULL)
		continue;

	      push_component (checker);

	      if (checker->interesting_seg (& data, & seg))
		{
		  /* Delay loading the contents of the segment until they are actually needed.  */
		  if (seg.data == NULL)
		    seg.data = elf_getdata_rawchunk (elf, seg.phdr->p_offset,
						     seg.phdr->p_filesz, ELF_T_BYTE);

		  ret &= checker->check_seg (& data, & seg);
		}
	      else
		einfo (VERBOSE2, "is not interested in segment %lu", cnt);

	      pop_component ();
	    }
	}
    }

  for (checker = first_checker; checker != NULL; checker = ((checker_internal *)(checker->internal))->next)
    if (checker->finish)
      {
	push_component (checker);
	ret &= checker->finish (& data);
	pop_component ();
      }

  return ret;
}

static Dwarf *
follow_debuglink (eu_checksec_data * data, Dwarf * dwarf)
{
  char *  canon_dir = NULL;
  char *  debugfile = NULL;
  int     fd;

  /* First try the build-id method.  */
  ssize_t       build_id_len;
  const void *  build_id_ptr;
  
  build_id_len = dwelf_elf_gnu_build_id (data->elf, & build_id_ptr);
  if (build_id_len > 0)
    {
      /* Compute the path to the debuginfo from the build id.
	 Since we know that we are running on a Fedora/RHEL
	 system we can just check the standard Fedora location:
	 
	  /usr/lib/debug/.build-id/NN/NN+NN.debug
	  
	where NNNN+NN is the build-id value as a hexadecimal
	string.  */

      const char * prefix = "/usr/lib/debug/.build-id/";
      const char * suffix = ".debug";
      char * debugfile = xmalloc (strlen (prefix)
				  + build_id_len * 2
				  + strlen (suffix) + 2);
      char * n = debugfile;
      unsigned char * d = (unsigned char *) build_id_ptr;
      
      n += sprintf (n, "%s%02x/", prefix, *d++);
      build_id_len --;
      while (build_id_len --)
	n += sprintf (n, "%02x", *d++);
      n += sprintf (n, suffix);

      einfo (VERBOSE, "%s: Look for build-id based debug info file: %s",
	     data->filename, debugfile);
      if ((fd = open (debugfile, O_RDONLY)) != -1)
	goto found;

      free (debugfile);
    }

  /* Now try using a .gnu.debuglink section.  */
  GElf_Word     crc;
  const char *  link;

  if ((link = dwelf_elf_gnu_debuglink (data->elf, & crc)) == NULL)
    return NULL;

  einfo (VERBOSE, "%s: Try to find separate debug file for: %s", data->filename, link);

  size_t canon_dirlen;

  /* Attempt to locate the separate file.  */
  canon_dir = lrealpath (data->filename);
  
  for (canon_dirlen = strlen (canon_dir); canon_dirlen > 0; canon_dirlen--)
    if (canon_dir[canon_dirlen - 1] == '/')
      break;
  canon_dir[canon_dirlen] = '\0';

#define DEBUGDIR_1 "/lib/debug"
#define DEBUGDIR_2 "/usr/lib/debug"
#define DEBUGDIR_3 "/usr/lib/debug/usr"
#define DEBUGDIR_4 "/usr/lib/debug/usr/lib64"

  debugfile = (char *) xmalloc (strlen (DEBUGDIR_1) + 1
				+ strlen (DEBUGDIR_2)
				+ strlen (DEBUGDIR_3)
				+ strlen (DEBUGDIR_4)
				+ canon_dirlen
				+ strlen (".debug/")
				+ strlen (link)
				+ 1);

  /* If we have been provided with a dwarf directory, try that first.  */
  if (dwarf_path)
    {
      sprintf (debugfile, "%s/%s", dwarf_path, link);
      einfo (VERBOSE2, " try: %s\n", debugfile);
      if ((fd = open (debugfile, O_RDONLY)) != -1)
	goto found;
    }
  
  /* First try in the current directory.  */
  sprintf (debugfile, "%s", link);
  einfo (VERBOSE2, " try: %s\n", debugfile);
  if ((fd = open (debugfile, O_RDONLY)) != -1)
    goto found;

  /* Then try in a subdirectory called .debug.  */
  sprintf (debugfile, ".debug/%s", link);
  einfo (VERBOSE2, " try: %s\n", debugfile);
  if ((fd = open (debugfile, O_RDONLY)) != -1)
    goto found;

  /* Then try in the same directory as the original file.  */
  sprintf (debugfile, "%s%s", canon_dir, link);
  einfo (VERBOSE2, "try: %s\n", debugfile);
  if ((fd = open (debugfile, O_RDONLY)) != -1)
    goto found;

  /* And the .debug subdirectory of that directory.  */
  sprintf (debugfile, "%s.debug/%s", canon_dir, link);
  einfo (VERBOSE2, "try: %s\n", debugfile);
  if ((fd = open (debugfile, O_RDONLY)) != -1)
    goto found;

  /* Try the first extra debug file root.  */
  sprintf (debugfile, "%s/%s", DEBUGDIR_2, link);
  einfo (VERBOSE2, "try: %s\n", debugfile);
  if ((fd = open (debugfile, O_RDONLY)) != -1)
    goto found;

  /* Try the first extra debug file root, with directory extensions.  */
  sprintf (debugfile, "%s%s%s", DEBUGDIR_2, canon_dir, link);
  einfo (VERBOSE2, " try: %s\n", debugfile);
  if ((fd = open (debugfile, O_RDONLY)) != -1)
    goto found;

  /* Try the second extra debug file root.  */
  sprintf (debugfile, "%s/%s", DEBUGDIR_3, link);
  einfo (VERBOSE2, " try: %s\n", debugfile);
  if ((fd = open (debugfile, O_RDONLY)) != -1)
    goto found;

  /* Try the third extra debug file root.  */
  sprintf (debugfile, "%s/%s", DEBUGDIR_4, link);
  einfo (VERBOSE2, " try: %s\n", debugfile);
  if ((fd = open (debugfile, O_RDONLY)) != -1)
    goto found;

  /* Then try in the global debugfile directory.  */
  sprintf (debugfile, "%s/%s", DEBUGDIR_1, link);
  einfo (VERBOSE2, " try: %s\n", debugfile);
  if ((fd = open (debugfile, O_RDONLY)) != -1)
    goto found;

  /* Then try in the global debugfile directory, with directory extensions.  */
  sprintf (debugfile, "%s%s%s", DEBUGDIR_1, canon_dir, link);
  einfo (VERBOSE2, " try: %s\n", debugfile);
  if ((fd = open (debugfile, O_RDONLY)) != -1)
    goto found;

  /* Try the first extra debug file root, with directory extensions.  */
  sprintf (debugfile, "%s%s%s", DEBUGDIR_2, canon_dir, link);
  einfo (VERBOSE2, " try: %s\n", debugfile);
  if ((fd = open (debugfile, O_RDONLY)) != -1)
    goto found;

  /* FIMXE: This is a workaround for a bug in the Fedora packaging
     system.  It is possible for the debuginfo files to be out of
     sync with their corresponding binary files.  Eg ld-2.29.1-23.fc28
     vs ld-2.29.1-22.fc28.debug_info.  So check for earlier versions
     of the debuginfo file in the directory where it is known that
     Fedora stores its debug files...  */
  char * dash = strrchr (link, '-');
  if (dash)
    {
      char * end;
      unsigned long revision = strtoul (dash + 1, & end, 10);
      while (revision > 1)
	{
	  --revision;
	  sprintf (debugfile, "%s%s%.*s%lu%s", DEBUGDIR_2, canon_dir, (int) (dash - link) + 1, link, revision, end);
	  einfo (VERBOSE2, " try: %s\n", debugfile);
	  if ((fd = open (debugfile, O_RDONLY)) != -1)
	    goto found;
	}
    }

  /* Failed to find the file.  */
  einfo (VERBOSE, "%s: Could not find separate debug file:  %s", data->filename, link);

  free (canon_dir);
  free (debugfile);
  return NULL;

 found:
  /* FIXME: We should verify the CRC value... */

  free (canon_dir);

  Dwarf * separate_debug_file;

  /* Now open the file.... */
  if ((separate_debug_file = dwarf_begin (fd, DWARF_C_READ)) == NULL)
    {
      einfo (VERBOSE, "%s: Failed to open separate debug file: %s", data->filename, debugfile);
      free (debugfile);
      return NULL;
    }

  einfo (VERBOSE, "%s: Found separate debug info file: %s", data->filename, debugfile);
  free (debugfile);

  /* Do not free debugfile - it might be referenced inside
     the structure returned by open_debug_file().  */
  return separate_debug_file;
}

/* -------------------------------------------------------------------- */

static bool
scan_dwarf (eu_checksec_data * data, Dwarf * dwarf, dwarf_walker func, void * ptr)
{
  Dwarf_Off  cuoffset;
  Dwarf_Off  ncuoffset = 0;
  size_t     hsize;

  while (dwarf_nextcu (dwarf, cuoffset = ncuoffset, & ncuoffset, & hsize, NULL, NULL, NULL) == 0)
    {
      Dwarf_Off cudieoff = cuoffset + hsize;
      Dwarf_Die cudie;

      if (dwarf_offdie (dwarf, cudieoff, & cudie) == NULL)
	{
	  einfo (ERROR, "%s: Empty CU", data->filename);
	  continue;
	}

      if (! func (data, dwarf, & cudie, ptr))
	return false;
    }

  return true;
}

/* Utility function to walk over the DWARF debug information in DATA calling FUNC
   on each DIE.  PTR is passed to FUNC along with a pointer to the DIE.
   If FUNC returns false the walk is terminated.
   Returns FALSE if the walk could not be executed.  */

bool
eu_checksec_walk_dwarf (eu_checksec_data * data, dwarf_walker func, void * ptr)
{
  Dwarf * dwarf;

  if (! data->dwarf_searched)
    {
      dwarf = dwarf_begin (data->fd, DWARF_C_READ);

      if (dwarf == NULL)
	dwarf = follow_debuglink (data, dwarf);

      data->dwarf_searched = true;

      if (dwarf == NULL)
	return einfo (VERBOSE2, "%s: Does not contain any DWARF information", data->filename);

      data->dwarf = dwarf;
    }

  if ((dwarf = data->dwarf) == NULL)
    return true;

  if (! scan_dwarf (data, dwarf, func, ptr))
    {
      /* Check for an alternate file.  */
      Dwarf * alt = dwarf_getalt (dwarf);

      if (alt != NULL)
	{
	  (void) dwarf_end (dwarf);
	  (void) scan_dwarf (data, alt, func, ptr);
	  data->dwarf = alt;
	}
    }

  /* We do not close the dwarf handle as we will probably want to use it again.  */
  return true;
}

/* -------------------------------------------------------------------- */

typedef struct walker_info
{
  ulong          start;
  ulong          end;
  const char **  name;
  bool           prefer_func;
} walker_info;

static bool
find_symbol_addr_using_dwarf (eu_checksec_data * data, Dwarf * dwarf, Dwarf_Die * die, void * ptr)
{
  assert (data != NULL && die != NULL && ptr != NULL);

  walker_info *  info;
  size_t         nlines;
  Dwarf_Lines *  lines;

  info = (walker_info *) ptr;

  dwarf_getsrclines (die, & lines, & nlines);

  if (lines != NULL && nlines > 0)
    {
      Dwarf_Line * line;
      size_t       indx = 1;

      einfo (VERBOSE2, "Scanning %ld lines in the DWARF line table", nlines);
      while ((line = dwarf_onesrcline (lines, indx)) != NULL)
	{
	  Dwarf_Addr addr;

	  dwarf_lineaddr (line, & addr);

	  if (addr >= info->start && addr <= info->end)
	    {
	      *(info->name) = dwarf_linesrc (line, NULL, NULL);
	      return false;
	    }

	  ++ indx;
	}
    }

  return true;
}

static const char *
find_symbol_in (eu_checksec_data * data, Elf_Scn * sym_sec, ulong addr, Elf64_Shdr * sym_hdr, bool prefer_func)
{
  Elf_Data * sym_data;
  if ((sym_data = elf_getdata (sym_sec, NULL)) == NULL)
    {
      einfo (VERBOSE2, "No symbol section data");
      return NULL;
    }

  bool use_sym = false;
  bool use_saved = false;
  GElf_Sym saved_sym;
  GElf_Sym sym;
  int symndx = 1;

  while (gelf_getsym (sym_data, symndx, & sym) != NULL)
    {
      if (sym.st_value == addr)
	{
	  if (!prefer_func || ELF64_ST_TYPE (sym.st_info) == STT_FUNC)
	    {
	      use_sym = true;
	      break;
	    }

	  memcpy (& saved_sym, & sym, sizeof sym);
	  use_saved = true;
	  continue;
	}

      /* As of version 3 of the protocol, start symbols are set at base address plus 2.  */
      if (!prefer_func && sym.st_value == addr + 2)
	{
	  use_sym = true;
	  break;
	}

      symndx++;
    }

  if (use_sym)
    return elf_strptr (data->elf, sym_hdr->sh_link, sym.st_name);
  else if (use_saved)
    return elf_strptr (data->elf, sym_hdr->sh_link, saved_sym.st_name);
  else
    return NULL;
}

/* Return the name of a symbol most appropriate for address range START..END.
   Returns NULL if no symbol could be found.  */

const char *
eu_checksec_find_symbol_for_address_range (eu_checksec_data * data, eu_checksec_section * sec, ulong start, ulong end, bool prefer_func)
{
  static const char * previous_result;
  static ulong        previous_start;
  static ulong        previous_end;

  const char * name = NULL;
  Elf64_Shdr   sym_shdr;
  Elf_Scn *    sym_sec = NULL;

  if (start == previous_start && end == previous_end)
    return previous_result;

  assert (data != NULL && sec != NULL);

  previous_start = start;
  previous_end   = end;

  einfo (VERBOSE2, "Look for a symbol matching address %#lx..%#lx", start, end);

  /* If the provided section has a link then try this first.  */
  if (sec != NULL && sec->shdr.sh_link)
    {
      sym_sec = elf_getscn (data->elf, sec->shdr.sh_link);
      read_section_header (data, sym_sec, & sym_shdr);

      if (sym_shdr.sh_type == SHT_SYMTAB || sym_shdr.sh_type == SHT_DYNSYM)
	{
	  name = find_symbol_in (data, sym_sec, start, & sym_shdr, prefer_func);
	  if (name != NULL)
	    return previous_result = name;
	}
    }

  /* Search for symbol sections.  */
  sym_sec = NULL;

  while ((sym_sec = elf_nextscn (data->elf, sym_sec)) != NULL)
    {
      read_section_header (data, sym_sec, & sym_shdr);

      if ((sym_shdr.sh_type == SHT_SYMTAB) || (sym_shdr.sh_type == SHT_DYNSYM))
	{
	  name = find_symbol_in (data, sym_sec, start, & sym_shdr, prefer_func);
	  if (name)
	    return previous_result = name;
	}
    }

  /* Now check DWARF data for an address match.  */
  walker_info walker;
  walker.start = start;
  walker.end = end;
  walker.name = & name;
  walker.prefer_func = prefer_func;
  eu_checksec_walk_dwarf (data, find_symbol_addr_using_dwarf, & walker);

  return previous_result = name;
}

/* -------------------------------------------------------------------- */

static bool process_elf (const char *, int, Elf *);

static bool
process_ar (const char * filename, int fd, Elf * elf)
{
  Elf *    subelf;
  Elf_Cmd  cmd = ELF_C_READ_MMAP;
  bool     ret = true;

  while ((subelf = elf_begin (fd, cmd, elf)) != NULL)
    {
      /* Get the header for this element.  */
      Elf_Arhdr * arhdr = elf_getarhdr (subelf);
      const char * fname = concat (filename, ":", arhdr->ar_name, NULL);

      /* Skip over the index entries.  */
      if (! streq (arhdr->ar_name, "/")
	  && ! streq (arhdr->ar_name, "//"))
	ret = process_elf (fname, fd, subelf);

      /* Get next archive element.  */
      cmd = elf_next (subelf);

      if (elf_end (subelf))
	return einfo (FAIL, "unable to close archive member %s", fname);

      free ((char *) fname);
    }

  return ret;
}

static bool
process_elf (const char * filename, int fd, Elf * elf)
{
  bool ret;

  switch (elf_kind (elf))
    {
    case ELF_K_AR:
      ret = process_ar (filename, fd, elf);
      break;
    case ELF_K_ELF:
      ret = run_checkers (filename, fd, elf);
      break;
    default:
      if (ignore_unknown)
	return true;
      return einfo (WARN, "%s: is not an ELF format file", filename);
    }
  
  return ret;
}

static bool
process_rpm_file (const char * filename)
{
  /* It turns out that the simplest/most portable way to handle an rpm is
     to use the rpm2cpio and cpio programs to unpack it for us...  */
  char dirname[20];

  strcpy (dirname, "annocheck.XXXXXX");
  if (mkdtemp (dirname) == NULL)
    return einfo (WARN, "Faield to create temporary directory for processing rpm: %s", filename);

  einfo (VERBOSE2, "Created temporary directory: %s", dirname);

  char * fname;
  char * pname;
  char * command;
  char * cwd = getcwd (NULL, 0);

  if (filename[0] != '/')
    fname = concat (cwd, "/", filename, NULL);
  else
    fname = concat (filename, NULL);

  if (progname[0] != '/' && strchr (progname, '/'))
    pname = concat (cwd, "/", progname, NULL);
  else
    pname = concat (progname, NULL);
    
  command = concat (/* Change into the temporary directory.  */
		    "cd ", dirname,
		    /* Convert the rpm to cpio format.  */
		    " && rpm2cpio ", fname,
		    /* Pipe the output into cpio in order to extract the files.  */
		    " | cpio -dium --quiet",
		    /* Run annocheck on the files in the directory, skipping unknown file types,
		       and prefixing the output with the rpm name.  */
		    " && ", pname, " --ignore-unknown ",
		    "--prefix ", lbasename (filename),
		    " ", saved_args ? saved_args : "",
		    " .",
		    /* Then move out of the directory.  */
		    " && cd ..",
		    /* And delete it.  */
		    " && rm -r ", dirname,
		    NULL);

  einfo (VERBOSE2, "Running rpm extractor command sequence: %s", command);
  if (system (command))
    return einfo (WARN, "Failed to process rpm file: %s", filename);

  free (command);
  free (cwd);
  free (fname);
  free (pname);

  einfo (VERBOSE2, "Extraction successful");
  return true;
}

static bool
process_file (const char * filename)
{
  size_t       len;
  struct stat  statbuf;

  /* When ignoring unknown file types (which typically happens when processing the
     contents of an rpm), we do not follow symbolic links.  This allows us to detect
     and ignore these links.  */
  if ((ignore_unknown ? lstat (filename, & statbuf) : stat (filename, & statbuf)) < 0)
    {
      if (errno == ENOENT)
	return einfo (WARN, "'%s': No such file", filename);

      return einfo (SYS_WARN, "Could not locate '%s'", filename);
    }

  if (S_ISDIR (statbuf.st_mode))
    {
      DIR * dir = opendir (filename);

      if (dir == NULL)
	return einfo (SYS_WARN, "unable to read directory: %s", filename);

      struct dirent * entry;
      bool result = true;

      einfo (VERBOSE, "Scanning directory: '%s'", filename);
      while ((entry = readdir (dir)) != NULL)
	{
	  if (streq (entry->d_name, ".") || streq (entry->d_name, ".."))
	    continue;

	  /* FIXME: Memory leak...  */
	  result &= process_file (concat (filename, "/", entry->d_name, NULL));
	}

      closedir (dir);
      return result;
    }

  if (! S_ISREG (statbuf.st_mode))
    {
      if (ignore_unknown)
	return true;

      return einfo (WARN, "'%s' is not an ordinary file", filename);
    }

  if (statbuf.st_size < 0)
    return einfo (WARN, "'%s' has negative size, probably it is too large", filename);

  /* If the file is an RPM hand it off for separate processing.  */

  /* FIXME: the rpmReadPackageFile() function can generate a seg-fault
     when processing some rpms (eg: wireshark-cli-2.6.0-3.fc27.aarch64.rpm)
     so just check for a .rpm suffix first.  */
  if ((len = strlen (filename)) > 4 && streq (filename + len - 4, ".rpm"))
    return process_rpm_file (filename);
    
  FD_t rpm_fd;
  rpmts ts = 0;
  Header hdr;
  if ((rpm_fd = Fopen (filename, "r")) != NULL
      && rpmReadPackageFile (ts, rpm_fd, filename, & hdr) == RPMRC_OK)
    {
      bool res = process_rpm_file (filename);
      Fclose (rpm_fd);
      return res;
    }

  /* Otherwise open it and try to process it as an ELF file.  */
  int fd = open (filename, O_RDONLY);
  if (fd == -1)
    return einfo (SYS_WARN, "Could not open %s", filename);

  Elf * elf = elf_begin (fd, ELF_C_READ, NULL);
  if (elf == NULL)
    return einfo (WARN, "Unable to parse %s - maybe it is not an ELF file ?", filename);

  bool ret = process_elf (filename, fd, elf);

  if (elf_end (elf))
    return einfo (WARN, "Failed to close ELF file: %s", filename);

  if (close (fd))
    return einfo (SYS_WARN, "Unable to close: %s", filename);

  return ret;
}

static bool
process_files (void)
{
  bool result = true;

  while (num_files)
    result &= process_file (files [-- num_files]);

  return result;
}

/* -------------------------------------------------------------------- */

int
main (int argc, const char ** argv)
{
  if (elf_version (EV_CURRENT) == EV_NONE)
    {
      einfo (FAIL, "Could not initialise libelf");
      return EXIT_FAILURE;
    }

  if (rpmReadConfigFiles (NULL, NULL) != 0)
    {
      einfo (FAIL, "Could not initialise librpm");
      return EXIT_FAILURE;
    }

  if (! process_command_line (argc, argv))
    return EXIT_FAILURE;

  if (!process_files ())
    {
      /* FIXME: This is a hack.  When --ignore-unknown is active we
	 are probably processing an rpm, and we do not want the
	 return status from annocheck to stop the cleanup of the
	 temporary directory.  */
      if (ignore_unknown)
	return EXIT_SUCCESS;
      return EXIT_FAILURE;
    }

  return EXIT_SUCCESS;
}

/* -------------------------------------------------------------------- */

bool
eu_checksec_add_checker (struct checker * new_checker, uint major)
{
  if (major < major_version)
    return false;

  checker_internal * internal = XCNEW (checker_internal);

  new_checker->internal = internal;
  if (new_checker->interesting_sec)
    {
      internal->next_sec = first_sec_checker;
      first_sec_checker = new_checker;
    }

  if (new_checker->interesting_seg)
    {
      internal->next_seg = first_seg_checker;
      first_seg_checker = new_checker;
    }

  internal->next = first_checker;
  first_checker = new_checker;

  return true;
}
