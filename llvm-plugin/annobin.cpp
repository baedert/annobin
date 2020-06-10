#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/LTO/legacy/LTOCodeGenerator.h"
#include "annobin-global.h"
#include <cstring>
#include <cctype>
#include <cstdarg>
#include <sstream>

using namespace llvm;
namespace
{
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
    const unsigned int  version = ANNOBIN_VERSION;
    char const *        fileStart = nullptr;
    char const *        fileEnd = nullptr;
    unsigned int        optLevel;

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
	      if (start_symbol == fileStart)
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
		  OPEN, fileStart, fileEnd,
		  GNU_BUILD_ATTRS_SECTION_NAME);
    }

    void
    OutputStringNote (Module &      module,
		      const char    string_type,
		      const char *  string,
		      const char *  name_description)
    {
      unsigned int len = strlen (string);
      char * buffer;

      buffer = (char *) malloc (len + 5);

      sprintf (buffer, "GA%c%c%s", STRING, string_type, string);

      verbose ("Record %s as '%s'", name_description, string);
      /* Be kind to readers of the assembler source, and do
	 not put control characters into ascii strings.  */
      OutputNote (module,
		  buffer, len + 5, isprint (string_type), name_description,
		  OPEN, fileStart, fileEnd, GNU_BUILD_ATTRS_SECTION_NAME);

      free (buffer);
    }

  public:
    static char ID;
    AnnobinModulePass() : ModulePass (ID)
    {
      if (getenv ("ANNOBIN_VERBOSE") != NULL
	  && ! streq (getenv ("ANNOBIN_VERBOSE"), "false"))
	be_verbose = true;
    }

    void
    setOptLevel (unsigned int val)
    {
      optLevel = val;
    }

    virtual StringRef
    getPassName (void) const
    {
      return "Annobin Module Pass";
    }
    
    virtual bool
    runOnModule (Module & module)
    {
      static char buf [6400]; // FIXME: Use a dynamic string.
      std::string filename = module.getSourceFileName ();

      // Generate start and end symbols.
      convert_to_valid_symbol_name (filename);
      verbose ("Generate start and end symbols based on: %s", filename.c_str ());
      fileStart = concat ("_annobin_", filename, "_start");
      fileEnd   = concat ("_annobin_", filename, "_end");

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
	       fileStart, fileStart, fileStart, fileStart,
	       fileEnd, fileEnd, fileEnd, fileEnd);

      module.appendModuleInlineAsm (buf);

      
      // Generate version notes.
      sprintf (buf, "%d%c%d", SPEC_VERSION, ANNOBIN_TOOL_ID_LLVM, version);
      OutputStringNote (module,
			GNU_BUILD_ATTRIBUTE_VERSION, buf,
			"version note");

      sprintf (buf, "annobin built by llvm version %s", LLVM_VERSION_STRING);
      OutputStringNote (module, GNU_BUILD_ATTRIBUTE_TOOL,
			buf, "tool note (plugin built by)");

      sprintf (buf, "running on %s", LTOCodeGenerator::getVersionString ());
      OutputStringNote (module, GNU_BUILD_ATTRIBUTE_TOOL,
			buf, "tool note (running on)");

      
      // Generate a PIE note.
      unsigned int val;
      if (module.getPIELevel () > 0)
	val = 4;
      else if (module.getPICLevel () > 0)
	val = 2;
      else
	val = 0;

      char pic[2] = {GNU_BUILD_ATTRIBUTE_PIC, 0};
      OutputNumericNote (module, pic, val, "PIE");


      // Generate FORTIFY, SAFE STACK anf STACK PROT STRONG notes.
      //
      // Unfortunately, since we are looking at the IR we have no access
      // to any preprocessor defines.  Instead we look for references to
      // functions that end in *_chk.  This is not a perfect heuristic by
      // any means, but it is the best that I can think of for now.
      bool stack_prot_strong_found = false;
      bool safe_stack_found = false;
      bool fortify_found = false;
      for (auto GI = module.begin(), GE = module.end(); GI != GE; ++GI)
	{
	  StringRef Name = GI->getName();
	  // FIXME: Surely there is a better way to do this.
	  Function * func = module.getFunction (Name);

	  if (func)
	    {
	      if (! stack_prot_strong_found
		  && func->hasFnAttribute (Attribute::StackProtectStrong))
		{
		  char prot[2] = {GNU_BUILD_ATTRIBUTE_STACK_PROT, 0};
		  OutputNumericNote (module, prot, 3, "Stack Proctector Strong");
		  stack_prot_strong_found = true;
		}

	      if (! safe_stack_found
		  && func->hasFnAttribute(Attribute::SafeStack))
		{
		  // FIXME: Using the stack_clash note is not quite correct, but will do for now.
		  OutputNumericNote (module, "stack_clash", 1, "SafeStack attribute");
		  safe_stack_found = true;
		}
	    }
	  
	  if (fortify_found == false
	      && Name.take_back(4) == "_chk")
	    {
	      OutputNumericNote (module, "FORTIFY", 2, "_FORTITFY_SOURCE used (probably)");
	      fortify_found = true;
	    }

	  if (safe_stack_found && fortify_found && stack_prot_strong_found)
	    break;
	}

      if (! stack_prot_strong_found)
	OutputNumericNote (module, "StackProtStrong", 0, "Stack Proctector Strong");
      if (! safe_stack_found)
	OutputNumericNote (module, "SafeStack", 0, "SafeStack attribute");
      // Do not worry about missing FORTIFY functions.
      
      // Generate a GOW note.
      val = optLevel;
      if (val > 3)
	val = 3;
      // The optimization level occupies bits 9..11 of the GOW value.
      val <<= 9;
      // FIXME: For now we lie and say that -Wall was used.
      val |= 1 << 14;
      verbose ("optimization level is %u", optLevel);
      OutputNumericNote (module, "GOW", val, "Optimization Level");

      
      // Generate a cf-protection note.
      val = 0;
      if (module.getModuleFlag("cf-protection-branch"))
	val += 1;
      if (module.getModuleFlag("cf-protection-return"))
	val += 2;
      // We bias the value by 1 so that we do not get confused by a zero value.
      val += 1;
      OutputNumericNote (module, "cf_protection", val, "Control Flow protection");

#if 0      
      if (be_verbose)
	{
	  verbose ("Available module flags:");
	  SmallVector<Module::ModuleFlagEntry, 8> ModuleFlags;
	  module.getModuleFlagsMetadata(ModuleFlags);
	  for (const llvm::Module::ModuleFlagEntry &MFE : ModuleFlags)
	    inform ("  %s", MFE.Key->getString());
	}
#endif 
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

  }; // End of class AnnobinModulePass 

  Pass *
  createAnnobinModulePass (int optLevel)
  {
    AnnobinModulePass * p;

    verbose ("Creating Module Pass");
    p = new AnnobinModulePass;
    // FIXME: There must surely be a way to access this information from with the Module class.
    p->setOptLevel (optLevel);
    return p;
  }
}

char AnnobinModulePass::ID = 0;

static void
registerAnnobinModulePass (const PassManagerBuilder & PMB,
			   legacy::PassManagerBase & PM)
{
  static RegisterPass<AnnobinModulePass> X("annobin", "Annobin Module Pass");
  PM.add (createAnnobinModulePass ((int) PMB.OptLevel));
}

// NB. The choice of when to run the passes is critical.  Using
// EP_EarlyAsPossible for example will run all the passes as Function passes,
// even if they are Module passes.  Whist using EP_ModuleOptimizerEarly will
// not run the pass at -O0.  Hence we use three different pass levels.
static RegisterStandardPasses
RegisterMyPass2 (PassManagerBuilder::EP_EnabledOnOptLevel0, registerAnnobinModulePass);

static RegisterStandardPasses
RegisterMyPass3 (PassManagerBuilder::EP_ModuleOptimizerEarly, registerAnnobinModulePass);

// -------------------------------------------------------------------------------------
// Function Pass

using namespace llvm;
namespace
{
  class AnnobinFunctionPass : public FunctionPass
  {
    static char ID;
  public:
    AnnobinFunctionPass() : FunctionPass (ID) {}

    virtual bool
    runOnFunction (Function & F)
    {
      // FIXME: Need to figure out how to get to the Module class from here.
      Module * M = F.getParent();
      verbose ("Checking function %s in Module %p", F.getName(), M);
      return false;
    }

    virtual StringRef
    getPassName (void) const
    {
      return "Annobin Function Pass";
    }
  };
}

char AnnobinFunctionPass::ID = 0;

static void
registerAnnobinFunctionPass (const PassManagerBuilder & PMB,
			     legacy::PassManagerBase & PM)
{
  PM.add (new AnnobinFunctionPass ());
}

static RegisterStandardPasses
RegisterMyPass1 (PassManagerBuilder::EP_EarlyAsPossible, registerAnnobinFunctionPass);
