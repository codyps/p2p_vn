#include <stdio.h>
#include <stdarg.h> /* va_* */
#include <string.h> /* strerror */
#include <stdlib.h> /* exit */

#include "routing.h"
#include "debug.h"

void mac_address_print(ether_addr_t mac, FILE *out)
{

}


__attribute__((format(printf,5,6)))
void error_at_line(int status, int errnum, const char *filename,
                   unsigned int linenum, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	fflush(stdout);

	fprintf(stderr, "%s:%u :", filename, linenum);

	if (errnum)
		fprintf(stderr, "%s : ", strerror(errnum));

	vfprintf(stderr, format, ap);

	fputc('\n',stderr);

	fflush(stderr);

	va_end(ap);
	if (status)
		exit(status);
}
