#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;
namespace
{
  class AnnobinModulePass : public ModulePass
  {
  public:
    static char ID;
    AnnobinModulePass() : ModulePass (ID) {}

    virtual bool
    runOnModule (Module &M)
    {
      if (M.getPICLevel() == PICLevel::NotPIC)
	errs() << "no PIC\n";
      else
	errs() << "PIC enabled\n";
      
      return false; // Module not modified.
    }
  };

  Pass *
  createAnnobinModulePass (void)
  {
    errs() << "Creating Module Pass\n";
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
      errs() << "Checking function " << F.getName () << "\n";
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

  // Warning: PM.add() can only be used to add Function passes.
  // It does not work for Module passes.
  PM.add (createAnnobinModulePass());
  
  errs() << "Optimization level is " << PMB.OptLevel << "\n";
}

static RegisterStandardPasses
RegisterMyPass (PassManagerBuilder::EP_ModuleOptimizerEarly, registerAnnobinPasses);
