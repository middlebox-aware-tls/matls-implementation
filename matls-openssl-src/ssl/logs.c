#include "logs.h"

unsigned long get_current_microseconds()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (1000000 * (tv.tv_sec) + tv.tv_usec);
}
