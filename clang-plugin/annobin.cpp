
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Lex/PreprocessorOptions.h"
#include "clang/Sema/Sema.h"
#include "llvm/Support/raw_ostream.h"
using namespace clang;

/* Version number.  NB: Keep the numeric and string versions in sync
   Also, keep in sync with the major_version and minor_version definitions
   in annocheck/annocheck.c.
   FIXME: This value should be defined in only one place...  */
static unsigned int   annobin_version = 901;
static const char *   version_string = N_("Version 901");


namespace
{
  // Dummy AST consumer, needed because plugins must have one.
  class AnnobinConsumer : public ASTConsumer
  {
    CompilerInstance &Instance;

  public:
    AnnobinConsumer(CompilerInstance &Instance) : Instance(Instance) {}

    bool
    HandleTopLevelDecl (DeclGroupRef DG) override
    {
      return true;
    }

    void
    HandleTranslationUnit (ASTContext& context) override
    {
    }   
  };

  // The real work of annobin is done in this class.
  class AnnobinAction : public PluginASTAction
  {
  private:
    bool enabled = true;
    bool verbose = false;

  protected:
    std::unique_ptr<ASTConsumer>
    CreateASTConsumer (CompilerInstance &CI, llvm::StringRef) override
    {
      CheckOptions (CI);
      // We have to have an AST consumer, even if it is a dummy.
      return llvm::make_unique<AnnobinConsumer>(CI);
    }

    // Automatically run the plugin
    PluginASTAction::ActionType 
    getActionType (void) override
    {
      return AddAfterMainAction;
    }

    // We do not want the plugin to stop the compilation of the binary.
    bool
    usesPreprocessorOnly (void) const override
    {
      return false;
    }

    // Handle any options passed to the plugin.
    bool
    ParseArgs (const CompilerInstance &CI, const std::vector<std::string> &args) override
    {
      for (unsigned i = 0, e = args.size(); i < e; ++i)
	{
	  if (args[i] == "help")
	    llvm::errs() << "Annobin plugin: supported options:\n\
  help      Display this message\n\
  disable   Disable the plugin\n\
  enable    Reenable the plugin if it has been disabled\n\
  version   Displays the version number\n\
  verbose   Produce descriptive messages whilst working\n";
	  else if (args[i] == "disable")
	    enabled = false;
	  else if (args[i] == "enable")
	    enabled = true;
	  else if (args[i] == "version")
	    llvn::errs() << "Annobin plugin for clang version " << annobin_version << "\n";
	  else if (args[i] == "verbose")
	    verbose = true;
	  else
	    llvm::errs() << "Annobin plugin: error: unknown option: " << args[i] << "\n";
	}

      return true;
    }

    void
    CheckOptions (CompilerInstance &CI)
    {
      if (! enabled)
	return;

      const CodeGenOptions &CodeOpts = CI.getCodeGenOpts ();

      llvm::errs() << "cf-protection: " << CodeOpts.CFProtectionReturn << "\n";

      
      const LangOptions &lang_opts = CI.getLangOpts ();
      if (lang_opts.ModuleFeatures.empty ())
	{
	  llvm::errs() << "No language module features\n";
	}
      else
	{
	  for (StringRef Feature : lang_opts.ModuleFeatures)
	    llvm::errs() << "Language module features: " << Feature << "\n";
	}

      llvm::errs() << "setjmp exceptions: " << lang_opts.SjLjExceptions << "\n";

      const PreprocessorOptions &pre_opts = CI.getPreprocessorOpts ();
      if (pre_opts.Macros.empty ())
	{
	  llvm::errs() << "No preprocessor macros\n";
	}
      else
	{
	  for (std::vector<std::pair<std::string, bool/*isUndef*/> >::const_iterator
		 i = pre_opts.Macros.begin (),
		 iEnd = pre_opts.Macros.end ();
	       i != iEnd; ++i)
	    {
	      if (! i->second)
		llvm::errs() << "Define: " << i->first << "\n";
	    }
	}

      const TargetOptions &targ_opts = CI.getTargetOpts ();
      if (targ_opts.FeaturesAsWritten.empty ())
	{
	  llvm::errs() << "No target opts\n";
	}
      else
	{
	  for (unsigned i = targ_opts.FeaturesAsWritten.size(); i -- > 0;)
	    llvm::errs() << "Target feature: " << targ_opts.FeaturesAsWritten[i] << "\n";
	}
    }
  };
}

static FrontendPluginRegistry::Add<AnnobinAction>
X("annobin", "annotate binary output");
