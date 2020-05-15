#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "annobin-global.h"
#include <cstring>
#include <cctype>
#include <cstdarg>
#include <sstream>

using namespace llvm;
namespace
{
  static const unsigned int   annobin_version = ANNOBIN_VERSION;
  static bool                 be_verbose = false;
  static bool                 target_start_sym_bias = false;

  // Helper functions used throughout this file.
  template<class... Tys>
  char *
  concat (Tys const&... args)
  {
    std::ostringstream oss;

    (void) std::initializer_list<int>{((oss << args), 1)...};
    return strdup (oss.str().c_str());
  }

  static inline void
  inform (char const fmt[], ...)
  {
    va_list args;

    va_start (args, fmt);
    fflush (stdout);
    fprintf (stderr, "Annobin: ");
    vfprintf (stderr, fmt, args);
    fputc ('\n', stderr);
    va_end (args);
  }

  static inline void
  verbose (char const fmt[], ...)
  {
    if (! be_verbose)
      return;

    va_list args;

    va_start (args, fmt);
    fflush (stdout);
    fprintf (stderr, "Annobin: ");
    vfprintf (stderr, fmt, args);
    fputc ('\n', stderr);
    va_end (args);
  }

  static inline void
  ice (char const fmt[], ...)
  {
    va_list args;

    va_start (args, fmt);
    fflush (stdout);
    fprintf (stderr, "Annobin: Internal Error: ");
    vfprintf (stderr, fmt , args);
    fputc ('\n', stderr);
    va_end (args);
    exit (EXIT_FAILURE);
  }

  class AnnobinModulePass : public ModulePass
  {
  private:
    char const *  annobin_current_file_start = nullptr;
    char const *  annobin_current_file_end = nullptr;

  public:
    static char ID;
    AnnobinModulePass() : ModulePass (ID)
    {
      if (getenv ("ANNOBIN_VERBOSE") != NULL
	  && ! streq (getenv ("ANNOBIN_VERBOSE"), "false"))
	be_verbose = true;
    }

    virtual bool
    runOnModule (Module & module)
    {
      static char buf [6400]; // FIXME: Use a dynamic string.
      std::string filename = module.getModuleIdentifier ();

      convert_to_valid_symbol_name (filename);
      verbose ("Generate start and end symbols based on: %s", filename.c_str ());
      annobin_current_file_start = concat ("_annobin_", filename, "_start");
      annobin_current_file_end   = concat ("_annobin_", filename, "_end");

      static const char START_TEXT[] = "\
\t.pushsection .text\n\
\t.hidden %s\n\
\t.type   %s, STT_NOTYPE\n\
\t.equiv  %s, .text\n\
\t.size   %s, 0\n\
\t.pushsection .text.zzz\n\
\t.hidden %s\n\
\t.type   %s, STT_NOTYPE\n\
\t.equiv  %s, .text.zzz\n\
\t.size   %s, 0\n\
\t.popsection\n";
      sprintf (buf, START_TEXT,
	       annobin_current_file_start, annobin_current_file_start, annobin_current_file_start, annobin_current_file_start,
	       annobin_current_file_end, annobin_current_file_end, annobin_current_file_end, annobin_current_file_end);

      module.appendModuleInlineAsm (buf);


      unsigned int val;
      if (module.getPIELevel () > 0)
	val = 4;
      else if (module.getPICLevel () > 0)
	val = 2;
      else
	val = 0;

      char pic[2] = {GNU_BUILD_ATTRIBUTE_PIC, 0};
      OutputNumericNote (module, pic, val, "PIE");
      
      return true; // Module has been modified.
    }

  private:

    static void
    convert_to_valid_symbol_name (std::string& name)
    {
      for( auto & c : name)
	if (!isalnum (c))
	  c = '_';
    }

    static void
    add_line_to_note (std::ostringstream & buffer, const char * text, const char * comment = nullptr)
    {
      buffer << '\t' << text;
      if (comment)
        buffer << " \t/* " << comment << " */";
      buffer << '\n';
    }

    void
    OutputNote (Module &      module,
		const char *  name,
		unsigned      namesz,
		bool          name_is_string,
		const char *  name_description,
		unsigned int  type,
		const char *  start_symbol,
		const char *  end_symbol,
		const char *  section_name)
    {
      std::ostringstream text_buffer;
      static char buf[1280];  // FIXME: We should be using a dynamically alloctaed buffer.
      static const int align = 4;

      sprintf (buf, ".pushsection %s, \"\", %%note", section_name);
      add_line_to_note (text_buffer, buf);
      sprintf (buf, ".balign %d", align);
      add_line_to_note (text_buffer, buf);

      if (name == nullptr)
	{
	  if (namesz)
	    ice ("null name with non-zero size");

	  add_line_to_note (text_buffer, ".dc.l 0", "no name");
	}
      else if (name_is_string)
	{
	  char buf2[128];  // FIXME: This should be dynamic and extendable.

	  if (strlen ((char *) name) != namesz - 1)
	    ice ("name string does not match name size");

	  sprintf (buf, ".dc.l %u", namesz);
	  sprintf (buf2, "size of name [= strlen (%s)]\n", name);
	  add_line_to_note (text_buffer, buf, buf2);
	}
      else
	{
	  sprintf (buf, ".dc.l %u", namesz);
	  add_line_to_note (text_buffer, buf, "size of name");
	}

      if (start_symbol != NULL)
	{
	  if (end_symbol == NULL)
	    ice ("start symbol without an end symbol");

	  add_line_to_note (text_buffer, ".dc.l 16", "description size [= 2 * sizeof (address)]");
	}
      else
	{
	  if (end_symbol != NULL)
	    ice ("end symbol without a start symbol");
	  add_line_to_note (text_buffer, ".dc.l 0", "no description");
	}

      sprintf (buf, ".dc.l %d", type);
      add_line_to_note (text_buffer, buf, "note type [256 = GLOBAL, 257 = FUNCTION]");

      if (name)
	{
	  if (name_is_string)
	    {
	      add_line_to_note (text_buffer, name, name_description);
	    }
	  else
	    {
	      sprintf (buf, ".dc.b");

	      for (unsigned i = 0; i < namesz; i++)
		sprintf (buf + strlen (buf), " %#x%c", ((unsigned char *) name)[i],
			 i < (namesz - 1) ? ',' : ' ');

	      add_line_to_note (text_buffer, buf, name_description);
	    }

	  if (namesz % align)
	    {
	      sprintf (buf, ".dc.b");
	      while (namesz % align)
		{
		  namesz++;
		  if (namesz % align)
		    strcat (buf, " 0,");
		  else
		    strcat (buf, " 0");
		}
	      add_line_to_note (text_buffer, buf, "padding");
	    }
	}

      if (start_symbol)
	{
	  sprintf (buf, ".quad %s", (char *) start_symbol);
	  if (target_start_sym_bias)
	    {
	      /* We know that the annobin_current_filename symbol has been
		 biased in order to avoid conflicting with the function
		 name symbol for the first function in the file.  So reverse
		 that bias here.  */
	      if (start_symbol == annobin_current_file_start)
		sprintf (buf + strlen (buf), "- %d", target_start_sym_bias);
	    }

	  add_line_to_note (text_buffer, buf, "start symbol");

	  sprintf (buf, ".quad %s", (char *) end_symbol);
	  add_line_to_note (text_buffer, buf, "end symbol");
	}

      add_line_to_note (text_buffer, "\t.popsection\n\n");

      module.appendModuleInlineAsm (text_buffer.str ());
    }
    
    void
    OutputNumericNote (Module &      module,
		       const char *  numeric_name,
		       unsigned int  val,
		       const char *  name_description)
    {
      char buffer [128];  // FIXME: This should be dynamic and extendable.
      unsigned len = sprintf (buffer, "GA%c%s", NUMERIC, numeric_name);
      char last_byte = 0;

      // For non-alphabetic names, we do not need, or want,
      // the terminating NUL at the end of the string.
      if (! isprint (numeric_name[0]))
	--len;

      verbose ("Record %s note as numeric value of %u", name_description, val);
	
      do
	{
	  last_byte = buffer[++len] = val & 0xff;
	  val >>= 8;
	}
      while (val);

      if (last_byte != 0)
	buffer[++len] = 0;

      OutputNote (module, buffer, len + 1, false, name_description,
		  OPEN, annobin_current_file_start, annobin_current_file_end,
		  GNU_BUILD_ATTRS_SECTION_NAME);
    }
  };

  Pass *
  createAnnobinModulePass (void)
  {
    verbose ("Creating Module Pass");
    return new AnnobinModulePass;
  }
  
  class AnnobinFunctionPass : public FunctionPass
  {
    static char ID;
  public:
    AnnobinFunctionPass() : FunctionPass (ID) {}

    virtual bool
    runOnFunction (Function & F)
    {
      verbose ("Checking function %s", F.getName ());
      return false;
    }
  };
}

char AnnobinModulePass::ID = 0;
char AnnobinFunctionPass::ID = 0;

static void
registerAnnobinPasses (const PassManagerBuilder & PMB,
		       legacy::PassManagerBase & PM)
{
  static RegisterPass<AnnobinModulePass> X("annobin", "Annobin Module Pass");

  PM.add (new AnnobinFunctionPass ());
  PM.add (createAnnobinModulePass());
  
  verbose ("Optimization level is %u", (int) PMB.OptLevel);
}

// NB. The choice of when to run the passes is critical.
// Using EP_EarlyAsPossible for example will run all the
// passes as Function passes, even if they are Module passes.
static RegisterStandardPasses
RegisterMyPass (PassManagerBuilder::EP_ModuleOptimizerEarly, registerAnnobinPasses);
