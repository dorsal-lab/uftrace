#include <pthread.h>

void *thread(void *arg) { return NULL;}

int main(int argc, char *argv[])
{
	pthread_t td;
	pthread_create(&td, NULL, &thread, NULL);
	return 0;
}
