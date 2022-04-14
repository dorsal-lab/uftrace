#include <stdio.h>
#include <libpatch/patch.h>

int main()
{
	patch_opt op;
	printf("size: %zu\n", sizeof(op));
	return 0;
}
