#include <lttng/tracef.h>

int main(int argc, char *argv[])
{
	lttng_ust_tracef("lttng ust tracepoint");
	return 0;
}
