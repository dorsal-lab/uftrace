#include <stdio.h>
#include <stdint.h>

#include <capstone/capstone.h>
#include <libresolver/porcelain.hpp>

int main(int argc, char *argv[])
{
	csh handle;
	uint64_t** results;
	libresolver_x86_resolve(handle, NULL, 0, 0, results, NULL);
	return 0;
}
