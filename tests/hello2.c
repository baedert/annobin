extern int extern_func (char *, int);
extern int extern_func2 (void);
extern int extern_func3 (void);

int 
foo (void) 
{ 
  return 2; 
}

int 
extern_func (char * array, int arg)
{
  return array[arg] * 44;
}

int
big_stack (int arg)
{
  char array [10240];
  return extern_func (array, arg) * extern_func2 () + extern_func3 ();
}

