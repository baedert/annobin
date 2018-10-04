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

/* Prefix used to isolate annobin symbols from program symbols.  */
#define ANNOBIN_SYMBOL_PREFIX ".annobin_"

/* -1: silent, 0: normal, 1: verbose, 2: very verbose.  */
ulong         verbosity = 0;

uint          major_version = 8;
uint          minor_version = 46;

static ulong         	num_files = 0;
static const char *     files[MAX_NUM_FILES];
static const char *     progname;
static const char *	base_component = "annocheck";
static const char *	component = "annocheck";
static bool             ignore_unknown = true;
static char *           saved_args = NULL;
static char *           prefix = "";
static const char *     debug_rpm = NULL;
static const char *     debug_rpm_dir = NULL;
static const char *     dwarf_path = NULL;
static uint             level = 0;
static const char *     tmpdir = NULL;

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

  /* Name of the datafile used to share data with other iterations.  */
  const char *     datafile;

} checker_internal;
  
/* -------------------------------------------------------------------- */
/* Print a message on stdout or stderr.  Returns FALSE (for error
   messages) so that it can be used as a terminator in boolean functions.  */

bool
einfo (einfo_type type, const char * format, ...)
{
  FILE *        file;
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
      file   = stdout;
      res    = true;
      break;
    case INFO:
      file   = stdout;
      res    = true;
      break;
    case PARTIAL:
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

  const char *  do_newline;
  const char    c = format[strlen (format) - 1];
  if (c == '\n' || c == ' ')
    do_newline = "";
  else if (c == '.' || c == ':')
    do_newline = "\n";
  else
    do_newline = ".\n";

  if (pref)
    fprintf (file, "%s: ", pref);

  if (!PARTIAL && prefix[0])
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
push_component (checker * tool)
{
  component = tool->name;
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

  checker * tool;
  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
    if (tool->version)
      {
	push_component (tool);
	tool->version ();
	pop_component ();
      }
}

static void
usage (void)
{
  einfo (INFO, "Runs various scans on the given files");
  einfo (INFO, "Useage: %s [options] <file(s)>", component);
  einfo (INFO, " Options are:");
  einfo (INFO, "   --debug-rpm=<FILE> [Find separate dwarf debug information in <FILE>]");
  einfo (INFO, "   --dwarf-dir=<DIR>  [Look in <DIR> for separate dwarf debug information files]");
  einfo (INFO, "   --help             [Display this message & exit]");
  einfo (INFO, "   --ignore-unknown   [Do not complain about unknown file types][default]");
  einfo (INFO, "   --report-unknown   [Do complain about unknown file types]");
  einfo (INFO, "   --quiet            [Do not print anything, just return an exit status]");
  einfo (INFO, "   --verbose          [Produce informational messages whilst working.  Repeat for more information]");
  einfo (INFO, "   --version          [Report the verion of the tool & exit]");

  einfo (INFO, "The following options are internal to the scanner and not expected to be supplied by the user:");
  einfo (INFO, "   --prefix=<TEXT>    [Include <TEXT> in the output description]");
  einfo (INFO, "   --tmpdir=<NAME>    [Absolute pathname of a temporary directory used to pass data between iterations]");
  einfo (INFO, "   --level=<N>        [Recursion level of the scanner]");

  einfo (INFO, "The following scanning tools are available:");

  checker * tool;
  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
    {
      push_component (tool);
      einfo (PARTIAL, "\n");
      if (tool->usage)
	tool->usage ();
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
      const char *  arg = argv[a];
      bool          used = false;
      checker *     tool;

      ++ a;

      for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
	if (tool->process_arg != NULL)
	  {
	    push_component (tool);
	    if (tool->process_arg (arg, argv, argc, & a))
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
	  const char *  parameter;
	  const char * orig_arg = arg;

	  arg += (arg[1] == '-' ? 2 : 1);
	  switch (*arg)
	    {
	    case 'h': /* --help */
	      usage ();
	      exit (EXIT_SUCCESS);

	    case 'i': /* --ignore-unknown  */
	      ignore_unknown = true;
	      break;

	    case 'r': /* --report-unknown  */
	      ignore_unknown = false;
	      break;

	    case 'q': /* --quiet */
	      save_arg (orig_arg);
	      verbosity = -1UL;
	      break;

	    case 'd': /* --debug-rpm or --dwarf-path */
	      parameter = strchr (arg, '=');
	      if (parameter == NULL)
		parameter = argv[a++];
	      else
		parameter ++;

	      if (strncmp (arg, "dwarf-dir", 9) == 0)
		dwarf_path = parameter;
	      else if (strncmp (arg, "debug-rpm", 9) == 0)
		debug_rpm = parameter;
	      else
		goto unknown_arg;
		  
	      if (parameter[0] != '/')
		{
		  const char * tmp;
		  /* Convert a relative path to an absolute one so that if/when
		     we recurse into a directory, the path will remain valid.  */
		  if (parameter == argv[a-1])
		    tmp = concat (orig_arg, " ", getcwd (NULL, 0), "/", parameter, NULL);
		  else if (debug_rpm == parameter)
		    tmp = concat ("--debug-rpm=", getcwd (NULL, 0), "/", parameter, NULL);
		  else /* dwarf_path == parameter  */
		    tmp = concat ("--dwarf-dir=", getcwd (NULL, 0), "/", parameter, NULL);
		  save_arg (tmp);
		  free ((void *) tmp);
		}
	      else
		{
		  save_arg (orig_arg);
		  if (parameter == argv[a-1])
		    save_arg (parameter);
		}

	      if (dwarf_path != NULL && debug_rpm != NULL)
		{
		  static bool warned = false;
		  if (! warned)
		    einfo (WARN, "Behaviour is udnefined when both --debug-rpm and --dwarf-dir are specified");
		  warned = true;
		}
	      break;

	    case 'p': /* --prefix  */
	      save_arg (orig_arg);
	      parameter = strchr (arg, '=');
	      if (parameter == NULL)
		parameter = argv[a++];
	      else
		parameter ++;
	      /* Prefix arguments accumulate.  */
	      prefix = concat (prefix, parameter, NULL);
	      break;

	    case 'l': /* --level */
	      parameter = strchr (arg, '=');
	      if (parameter == NULL)
		parameter = argv[a++];
	      else
		parameter ++;	      
	      level = strtoul (parameter, NULL, 0);
	      if (level < 1)
		{
		  einfo (WARN, "improper --level option: %s", parameter);
		  level = 1;
		}
	      break;

	    case 't': /* --tmpdir */
	      if (const_strneq (arg, "tmpdir"))
		{
		  parameter = strchr (arg, '=');
		  if (parameter == NULL)
		    parameter = argv[a++];
		  else
		    parameter ++;	      
		  tmpdir = parameter;
		  assert (tmpdir[0] == '/');
		}
	      else
		goto unknown_arg;
	      break;
	      
	    case 'v': /* --verbose or --version */
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
annocheck_walk_notes (annocheck_data * data, annocheck_section * sec, note_walker func, void * ptr)
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
read_section_header (annocheck_data * data, Elf_Scn * section, Elf64_Shdr * s64hdr)
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
  annocheck_data data;

  memset (& data, 0, sizeof data);
  data.full_filename = filename;
  data.filename = BE_VERBOSE ? filename : lbasename (filename);
  data.fd = fd;
  data.elf = elf;
  data.is_32bit = gelf_getclass (elf) == ELFCLASS32;

  checker * tool;

  /* Call the checker start functions.  */
  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
    if (tool->start_file)
      {
	push_component (tool);
	tool->start_file (& data);
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
	  annocheck_section  sec;

	  memset (& sec, 0, sizeof sec);

	  sec.scn = scn;
	  read_section_header (& data, scn, & sec.shdr);
	  sec.secname = elf_strptr (elf, shstrndx, sec.shdr.sh_name);	  

	  /* Note - do not skip empty sections, they may still be interesting to some tools.
	     If a tool is not interested in an empty section, it can always determine this
	     in its interesting_sec() function.  */
	  einfo (VERBOSE2, "%s: Examining section %s", filename, sec.secname);

	  /* Walk the checkers, asking each in turn if they are interested in this section.  */
	  for (tool = first_sec_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next_sec)
	    {
	      if (tool->interesting_sec == NULL)
		continue;

	      push_component (tool);

	      if (tool->interesting_sec (& data, & sec))
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

		      assert (tool->check_sec != NULL);
		      ret &= tool->check_sec (& data, & sec);
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
      size_t phnum, cnt;

      elf_getphdrnum (elf, & phnum);

      for (cnt = 0; cnt < phnum; ++cnt)
	{
	  GElf_Phdr   mem;
	  annocheck_segment seg;

	  memset (& seg, 0, sizeof seg);

	  seg.phdr = gelf_getphdr (elf, cnt, & mem);
	  seg.number = cnt;

	  einfo (VERBOSE2, "%s: considering segment %lu", filename, (unsigned long) cnt);

	  for (tool = first_seg_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next_seg)
	    {
	      if (tool->interesting_seg == NULL)
		continue;

	      push_component (tool);

	      if (tool->interesting_seg (& data, & seg))
		{
		  /* Delay loading the contents of the segment until they are actually needed.  */
		  if (seg.data == NULL)
		    seg.data = elf_getdata_rawchunk (elf, seg.phdr->p_offset,
						     seg.phdr->p_filesz, ELF_T_BYTE);

		  assert (tool->check_seg != NULL);
		  ret &= tool->check_seg (& data, & seg);
		}
	      else
		einfo (VERBOSE2, "is not interested in segment %lu", (unsigned long) cnt);

	      pop_component ();
	    }
	}
    }

  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
    if (tool->end_file)
      {
	push_component (tool);
	ret &= tool->end_file (& data);
	pop_component ();
      }

  return ret;
}

/* Like process_rpm_file, except that the rpm is just
   extracted and then left untouched.  Returns the name
   of the directory holding the rpm contents.  */

static const char *
extract_rpm_file (const char * filename)
{
  static char dirname[32];

  if (debug_rpm_dir != NULL)
    return debug_rpm_dir;

  dirname[0] = 0;
  strcpy (dirname, "annocheck.debuginfo.XXXXXX");
  if (mkdtemp (dirname) == NULL)
    {
      einfo (ERROR, "Failed to create temporary directory for debuginfo extraction: %s", filename);
      return NULL;
    }

  einfo (VERBOSE2, "Created temporary directory for debuginfo extraction: %s", dirname);

  char * fname;
  char * command;
  char * cwd = getcwd (NULL, 0);

  /* If filename is a relative path, convert it to an absolute one
     so that it can be found once we change into the temporary directory.  */
  if (filename[0] != '/')
    fname = concat (cwd, "/", filename, NULL);
  else
    /* This is just so that we can safely call free(fname) at the end.  */
    fname = concat (filename, NULL);

  if (access (fname, F_OK) == -1) 
    {
      einfo (SYS_ERROR, "Error reading rpm file file %s", fname);
      free (fname);
      return NULL;
    }

  command = concat (/* Change into the temporary directory.  */
		    "cd ", dirname,
		    /* Convert the rpm to cpio format.  */
		    " && rpm2cpio \"", fname, "\"",
		    /* Pipe the output into cpio in order to extract the files.  */
		    " | cpio -dium --quiet",
		    /* Then move out of the directory.  */
		    " && cd ..",
		    NULL);

  einfo (VERBOSE2, "Running rpm extractor command sequence: %s", command);
  fflush (stdin);
  
  if (system (command))
    {
      einfo (WARN, "Failed to extract rpm file: %s", filename);
      return NULL;
    }

  free (command);
  free (cwd);
  free (fname);

  einfo (VERBOSE2, "Extraction successful");
  return debug_rpm_dir = dirname;
}

#define TRY_DEBUG(format,args...)					\
  do									\
    {									\
      sprintf (debugfile, format, args);				\
      einfo (VERBOSE2, "%s:  try: %s", data->filename, debugfile);	\
      if ((fd = open (debugfile, O_RDONLY)) != -1)			\
	goto found;							\
    }									\
  while (0)

static Dwarf *
follow_debuglink (annocheck_data * data, Dwarf * dwarf)
{
  char *  canon_dir = NULL;
  char *  debugfile = NULL;
  int     fd;

  /* First try the build-id method.  */
  ssize_t       build_id_len;
  const void *  build_id_ptr;

  einfo (VERBOSE2, "%s: Attempting to locate separate debuginfo file", data->filename);

  build_id_len = dwelf_elf_gnu_build_id (data->elf, & build_id_ptr);
  if (build_id_len > 0)
    {
      /* Compute the path to the debuginfo from the build id.
	 Since we know that we are running on a Fedora/RHEL
	 system we can just check the standard Fedora location:
	 
	  /usr/lib/debug/.build-id/NN/NN+NN.debug
	  
	where NNNN+NN is the build-id value as a hexadecimal
	string.  */

      const char *     path = NULL;
      const char *     leadin = "/usr/lib/debug/.build-id";
      unsigned char *  d = (unsigned char *) build_id_ptr;
      char             build_id_dir[3];
      char *           build_id_name;
      char *           n;

      einfo (VERBOSE2, "%s: Testing possibilities based upon the build-id", data->filename);

      if (debug_rpm)
	/* If the user has told us an rpm file that contains
	   debug information then extract it and use it.  */
	path = extract_rpm_file (debug_rpm);
      else if (dwarf_path)
	path = dwarf_path;

      if (path == NULL)
	path = "";
      
      debugfile = n = xmalloc (strlen (leadin)
                               + strlen (path)
			       + build_id_len * 2
			       + strlen (".debug") + 6);
      
      sprintf (build_id_dir, "%02x", * d++);
      build_id_len --;
      build_id_name = n = xmalloc (build_id_len * 2 + 1);
      while (build_id_len --)
	n += sprintf (n, "%02x", *d++);      
      
      if (* path)
	{
	  /* If the user has supplied a directory to search then this might be
	     an unpacked debuginfo rpm.  So try the following possibilities:

	     <path>/NNNNN.debug
	     <path>/NN/NNNNN.debug
	     <path>/.build-id/NN/NNNN.debug
	     <path>/usr/lib/debug/.build-id/NN/NNNNN.debug */

          TRY_DEBUG ("%s/%s.debug", path, build_id_name);
          TRY_DEBUG ("%s/%s/%s.debug", path, build_id_dir, build_id_name);
          TRY_DEBUG ("%s/.build-id/%s/%s.debug", path, build_id_dir, build_id_name);
          TRY_DEBUG ("%s/%s/%s/%s.debug", path, leadin + 1, build_id_dir, build_id_name);
	}

      TRY_DEBUG ("%s/%s/%s.debug", leadin, build_id_dir, build_id_name);

      free (debugfile);
      einfo (VERBOSE2, "%s: Could not find separate debug based on build-id", data->filename);
    }

  /* Now try using a .gnu.debuglink section.  */
  GElf_Word     crc;
  const char *  link;

  if ((link = dwelf_elf_gnu_debuglink (data->elf, & crc)) == NULL)
    {
      einfo (VERBOSE2, "%s: Could not find separate debug file", data->filename);
      return NULL;
    }

  einfo (VERBOSE2, "%s: Testing possibilities based upon the debuglink", data->filename);

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
    TRY_DEBUG ("%s/%s", dwarf_path, link);

  /* If we have been pointed at an debuginfo rpm then try that next.  */
  if (debug_rpm)
    {
      const char * dir = extract_rpm_file (debug_rpm);
      TRY_DEBUG ("./%s/%s", dir, link);
      TRY_DEBUG ("./%s%s/%s", dir, DEBUGDIR_1, link);
      TRY_DEBUG ("./%s%s/%s", dir, DEBUGDIR_2, link);
      TRY_DEBUG ("./%s%s/%s", dir, DEBUGDIR_3, link);
      TRY_DEBUG ("./%s%s/%s", dir, DEBUGDIR_4, link);
    }
  
  /* next try in the current directory.  */
  TRY_DEBUG ("./%s", link);

  /* Then try in a subdirectory called .debug.  */
  TRY_DEBUG ("./.debug/%s", link);

  /* Then try in the same directory as the original file.  */
  TRY_DEBUG ("%s%s", canon_dir, link);

  /* And the .debug subdirectory of that directory.  */
  TRY_DEBUG ("%s.debug/%s", canon_dir, link);

  /* Try the first extra debug file root.  */
  TRY_DEBUG ("%s/%s", DEBUGDIR_2, link);

  /* Try the first extra debug file root, with directory extensions.  */
  TRY_DEBUG ("%s%s%s", DEBUGDIR_2, canon_dir, link);

  /* Try the second extra debug file root.  */
  TRY_DEBUG ("%s/%s", DEBUGDIR_3, link);

  /* Try the fourth extra debug file root.  */
  TRY_DEBUG ("%s/%s", DEBUGDIR_4, link);

  /* Then try in the global debugfile directory.  */
  TRY_DEBUG ("%s/%s", DEBUGDIR_1, link);

  /* Then try in the global debugfile directory, with directory extensions.  */
  TRY_DEBUG ("%s%s%s", DEBUGDIR_1, canon_dir, link);

  /* Try the first extra debug file root, with directory extensions.  */
  TRY_DEBUG ("%s%s%s", DEBUGDIR_2, canon_dir, link);

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

	  TRY_DEBUG ("%s%s%.*s%lu%s", DEBUGDIR_2, canon_dir, (int) (dash - link) + 1, link, revision, end);
	}
    }

  /* Failed to find the file.  */
  einfo (VERBOSE, "%s: Could not find separate debug file: %s", data->filename, link);
  
  free (canon_dir);
  free (debugfile);
  return NULL;

 found:
  /* FIXME: We should verify the CRC value.  */

  free (canon_dir);

  /* Now open the file...  */
  Dwarf * separate_debug_file = dwarf_begin (fd, DWARF_C_READ);

  if (separate_debug_file == NULL)
    einfo (VERBOSE, "%s: Failed to open separate debug file: %s", data->filename, debugfile);
  else
    einfo (VERBOSE2, "%s: Opened separate debug file: %s", data->filename, debugfile);

  free (debugfile);
  return separate_debug_file;
}

/* -------------------------------------------------------------------- */

static bool
scan_dwarf (annocheck_data * data, Dwarf * dwarf, dwarf_walker func, void * ptr)
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
annocheck_walk_dwarf (annocheck_data * data, dwarf_walker func, void * ptr)
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

  (void) scan_dwarf (data, dwarf, func, ptr);

  /* We used to call dwarf_getalt() if the scan failed to find anything.
     But that was a waste of time.  libdw will automatically load any
     alternate debug info files pointed to by sections in the binary.  */

  /* We do not close the dwarf handle as we will probably want to use it again.  */
  return true;
}

/* -------------------------------------------------------------------- */

static bool
ends_with (const char * string, const char * ending, const size_t end_len)
{
  size_t len = strlen (string);

  if (string == NULL
      || len <= end_len
      || ! streq (string + (len - end_len), ending))
    return false;
  return true;
}

static const char *
find_symbol_in (Elf * elf, Elf_Scn * sym_sec, ulong addr, Elf64_Shdr * sym_hdr, bool prefer_func)
{
  Elf_Data * sym_data;

  if ((sym_data = elf_getdata (sym_sec, NULL)) == NULL)
    {
      einfo (VERBOSE2, "No symbol section data");
      return NULL;
    }

  bool use_sym = false;
  bool use_saved = false;
  GElf_Sym saved_sym = {0};
  GElf_Sym sym;
  unsigned int symndx;

  for (symndx = 1; gelf_getsym (sym_data, symndx, & sym) != NULL; symndx++)
    {
      /* As of version 3 of the protocol, start symbols might be biased by 2.  */
      if (sym.st_value >= addr && sym.st_value <= addr + 2)
	{
	  if (prefer_func && GELF_ST_TYPE (sym.st_info) == STT_FUNC)
	    {
	      use_sym = true;
	      break;
	    }

	  const char * name = elf_strptr (elf, sym_hdr->sh_link, sym.st_name);
	  if (ends_with (name, "_end", strlen ("_end")))
	    continue;

	  if (ends_with (name, ".end", strlen (".end")))
	    continue;

	  if (! use_saved)
	    {
	      memcpy (& saved_sym, & sym, sizeof sym);
	      use_saved = true;
	    }
	  else
	    {
	      /* Save this symbol if it is a better fit than the currently
		 saved symbol.  */
	      if (GELF_ST_VISIBILITY (sym.st_other) != STV_HIDDEN
		  && GELF_ST_TYPE (sym.st_info) != STT_NOTYPE)
		memcpy (& saved_sym, & sym, sizeof sym);
	    }
	}
    }

  if (use_sym)
    return elf_strptr (elf, sym_hdr->sh_link, sym.st_name);

  if (use_saved)
    return elf_strptr (elf, sym_hdr->sh_link, saved_sym.st_name);

  return NULL;
}

typedef struct walker_info
{
  ulong          start;
  ulong          end;
  const char **  name;
  bool           prefer_func;
} walker_info;

static bool
find_symbol_addr_using_dwarf (annocheck_data * data, Dwarf * dwarf, Dwarf_Die * die, void * ptr)
{
  assert (data != NULL && die != NULL && ptr != NULL);

  walker_info * info = (walker_info *) ptr;

  /* If we are examining a separate debuginfo file then
     it might have a symbol table that we can use.  */
  if (data->elf != dwarf_getelf (dwarf))
    {
      Elf_Scn *    sym_sec = NULL;
      Elf *        elf = dwarf_getelf (dwarf);

      while ((sym_sec = elf_nextscn (elf, sym_sec)) != NULL)
	{
	  Elf64_Shdr   sym_shdr;

	  read_section_header (data, sym_sec, & sym_shdr);

	  if ((sym_shdr.sh_type == SHT_SYMTAB) || (sym_shdr.sh_type == SHT_DYNSYM))
	    {
	      const char * name;

	      name = find_symbol_in (elf, sym_sec, info->start, & sym_shdr, info->prefer_func);
	      if (name)
		{
		  *(info->name) = name;
		  return false;
		}
	    }
	}
    }

  size_t         nlines;
  Dwarf_Lines *  lines;

  dwarf_getsrclines (die, & lines, & nlines);

  if (lines != NULL && nlines > 0)
    {
      Dwarf_Line * line;
      size_t       indx = 1;

      einfo (VERBOSE2, "Scanning %ld lines in the DWARF line table", (unsigned long) nlines);
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

/* Return the name of a symbol most appropriate for address range START..END.
   Returns NULL if no symbol could be found.  */

const char *
annocheck_find_symbol_for_address_range (annocheck_data *     data,
					 annocheck_section *  sec,
					 ulong                start,
					 ulong                end,
					 bool                 prefer_func)
{
  static const char * previous_result;
  static ulong        previous_start;
  static ulong        previous_end;

  const char * name = NULL;
  Elf64_Shdr   sym_shdr;
  Elf_Scn *    sym_sec = NULL;

  if (start > end)
    return NULL;

  if (start == previous_start && end == previous_end)
    return previous_result;

  assert (data != NULL);

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
	  name = find_symbol_in (data->elf, sym_sec, start, & sym_shdr, prefer_func);
	  if (name != NULL)
	    goto found;

	}
    }

  /* Search for symbol sections.  */
  sym_sec = NULL;

  while ((sym_sec = elf_nextscn (data->elf, sym_sec)) != NULL)
    {
      read_section_header (data, sym_sec, & sym_shdr);

      if ((sym_shdr.sh_type == SHT_SYMTAB) || (sym_shdr.sh_type == SHT_DYNSYM))
	{
	  name = find_symbol_in (data->elf, sym_sec, start, & sym_shdr, prefer_func);
	  if (name)
	    goto found;
	}
    }

  /* Now check DWARF data for an address match.  */
  walker_info walker;
  walker.start = start;
  walker.end = end;
  walker.name = & name;
  walker.prefer_func = prefer_func;
  annocheck_walk_dwarf (data, find_symbol_addr_using_dwarf, & walker);

 found:
  /* If we have found an ".annobin_" prefixed symbol then skip the prefix.  */
  if (name && strncmp (name, ANNOBIN_SYMBOL_PREFIX, strlen (ANNOBIN_SYMBOL_PREFIX)) == 0)
    name += strlen (ANNOBIN_SYMBOL_PREFIX);

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

static const char *
itoa (uint level)
{
  switch (level)
    {
    case 0: return "0";
    case 1: return "1";
    case 2: return "2";
    case 3: return "3";
    default: return "4"; /* Can this ever be reached ?  */
    }
}

static bool
process_rpm_file (const char * filename)
{
  /* It turns out that the simplest/most portable way to handle an rpm is
     to use the rpm2cpio and cpio programs to unpack it for us...  */
  char dirname[32];

  strcpy (dirname, "annocheck.rpm.XXXXXX");
  if (mkdtemp (dirname) == NULL)
    return einfo (WARN, "Failed to create temporary directory for processing rpm: %s", filename);

  einfo (VERBOSE2, "Created temporary directory for rpm processing: %s", dirname);

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
		    " && rpm2cpio \"", fname, "\"",
		    /* Pipe the output into cpio in order to extract the files.  */
		    " | cpio -dium --quiet",
		    /* Run annocheck on the files in the directory, skipping unknown file types,
		       and prefixing the output with the rpm name.  */
		    " && ", pname, " --ignore-unknown ",
		    "--prefix \"", lbasename (filename), "\"",
		    /* Increment the recursion level.  */
		    " --level ", itoa (level + 1),
		    /* Pass on the name of the temporary data directory, if created.  */
		    tmpdir == NULL ? "" : " --tmpdir ",
		    tmpdir == NULL ? "" : tmpdir,
		    /* Then all the other options that the user has supplied.  */
		    " ", saved_args ? saved_args : "",
		    " .",
		    NULL);

  einfo (VERBOSE2, "Running rpm extractor command sequence: %s", command);
  fflush (stdin);

  int result = system (command);
  if (result == -1 || result == 127)
    return einfo (WARN, "Failed to process rpm file: %s", filename);

  free (command);
  free (cwd);
  free (fname);
  free (pname);

  /* Delete the temporary directory.  */
  command = concat ("rm -r ", dirname, NULL);
  if (system (command))
    einfo (WARN, "Failed to delete temporary directory: %s", dirname);
  free (command);

  einfo (VERBOSE2, "RPM processed successfully");
  return result == EXIT_SUCCESS;
}

static bool
process_file (const char * filename)
{
  size_t       len;
  struct stat  statbuf;

  /* Fast track ignoring of debuginfo files.
     FIXME: Maybe add other file extensions ?
     FIXME: Maybe check that the extension is at the end of the filename ?  */
  if (ignore_unknown && strstr (filename, ".debug"))
    return true;

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

      einfo (VERBOSE2, "Scanning directory: '%s'", filename);
      while ((entry = readdir (dir)) != NULL)
	{
	  if (streq (entry->d_name, ".") || streq (entry->d_name, ".."))
	    continue;

	  const char * file = concat (filename, "/", entry->d_name, NULL);
	  result &= process_file (file);
	  free ((char *) file);
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
  if ((rpm_fd = Fopen (filename, "r")) != NULL)
    {
      rpmts  ts = 0;
      Header hdr;
      bool   res = false;

      if (rpmReadPackageFile (ts, rpm_fd, filename, & hdr) == RPMRC_OK)
	res = process_rpm_file (filename);

      Fclose (rpm_fd);
      if (res)
	return true;
    }

  /* Otherwise open it and try to process it as an ELF file.  */
  int fd = open (filename, O_RDONLY);
  if (fd == -1)
    return einfo (SYS_WARN, "Could not open %s", filename);

  Elf * elf = elf_begin (fd, ELF_C_READ, NULL);
  if (elf == NULL)
    {
      close (fd);
      return einfo (WARN, "Unable to parse %s - maybe it is not an RPM or ELF file ?", filename);
    }

  bool ret = process_elf (filename, fd, elf);

  if (elf_end (elf))
    {
      close (fd);
      return einfo (WARN, "Failed to close ELF file: %s", filename);
    }

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

static const char *
create_tmpdir (void)
{
  static char temp[32];

  if (tmpdir != NULL)
    return tmpdir;

  /* This assert can be triggered if a tool defines an END_SCAN function
     but no START_SCAN function.  */
  assert (level == 0);

  strcpy (temp, "annocheck.data.XXXXXX");
  tmpdir = mkdtemp (temp);
  if (tmpdir == NULL)
    {
      einfo (ERROR, "Unable to make temporary data directory");
      return NULL;
    }

  tmpdir = concat (getcwd (NULL, 0), "/", tmpdir, NULL);
  einfo (VERBOSE2, "Created temporary directory for data transfer: %s", tmpdir);

  return tmpdir;
}

/* -------------------------------------------------------------------- */

int
main (int argc, const char ** argv)
{
  checker *     tool;
  bool          self_made_tmpdir = false;


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

  if (level == 0)
    einfo (INFO, "Version %d.%d", major_version, minor_version);
  
  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
    if (tool->start_scan != NULL)
      {
	checker_internal * internal = (checker_internal *)(tool->internal);

	if (internal->datafile == NULL)
	  {
	    if (tmpdir == NULL)
	      {
		assert (level == 0);
		tmpdir = create_tmpdir ();
		if (tmpdir == NULL)
		  return EXIT_FAILURE;
		self_made_tmpdir = true;
	      }

	    if (tmpdir[strlen (tmpdir) - 1] == '/')
	      internal->datafile = concat (tmpdir, tool->name, NULL);
	    else
	      internal->datafile = concat (tmpdir, "/", tool->name, NULL);
	  }

	push_component (tool);
	tool->start_scan (level, internal->datafile);
	pop_component ();
      }
  
  bool res = process_files ();

  for (tool = first_checker; tool != NULL; tool = ((checker_internal *)(tool->internal))->next)
    if (tool->end_scan != NULL)
      {
	checker_internal * internal = (checker_internal *)(tool->internal);

	if (internal->datafile == NULL)
	  {
	    einfo (ERROR, "data file should have already been created");
	    continue;
	  }
	push_component (tool);
	tool->end_scan (level, internal->datafile);
	pop_component ();

	free ((char *) internal->datafile);
      }
  
  if (debug_rpm_dir)
    rmdir (debug_rpm_dir);

  if (self_made_tmpdir)
    {
      assert (level == 0);
      assert (tmpdir != 0);
      rmdir (tmpdir);
    }

  return res ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* -------------------------------------------------------------------- */

bool
annocheck_add_checker (struct checker * new_checker, uint major)
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
