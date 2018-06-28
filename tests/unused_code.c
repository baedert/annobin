
int unused_func_1 (void) __attribute__((optimize("-O1"),__noinline__));

int
unused_func_1 (void)
{
  return 22;
}

int
extern_func2 (void)
{
  return 23;
}

int
extern_func3 (void)
{
  return 24;
}

int unused_func_2 (void) __attribute__((optimize("-O0"),__noinline__));

int
unused_func_2 (void)
{
  return 25;
}

int linkonce_func_1 (void) __attribute ((section (".gnu.linkonce.t.linkonce_func_1")));
int linkonce_func_1 (void) __attribute__((optimize("-O0"),__noinline__));

int
linkonce_func_1 (void)
{
  return 26;
}
