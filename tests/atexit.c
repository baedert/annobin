#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
int main()
{
        /* Print the address of the functions, to force an non-inline copy
           of these functions from libc_nonshared.a into the link.  */
        printf ("%p\n", atexit);
        return 0;
}
