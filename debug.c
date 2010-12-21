#include <stdio.h>
#include <stdarg.h> /* va_* */
#include <string.h> /* strerror */
#include <stdlib.h> /* exit */

#include "routing.h"
#include "debug.h"
int debug;

char *h_char = "0123456789abcdef";


void mac_address_print(ether_addr_t *mac, FILE *out)
{
	size_t i;
	for (i = 0; i < ETH_ALEN; i++) {
		fputc(h_char[0xF & mac->addr[i]], out);
		fputc(h_char[(mac->addr[i] >> 4) & 0xF], out);
	}

	fputs(" : ", out);
}


__attribute__((format(printf,5,6)))
void error_at_line(int status, int errnum, const char *filename,
                   unsigned int linenum, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	fflush(stdout);

	fprintf(stderr, "%s:%u : ", filename, linenum);

	if (errnum)
		fprintf(stderr, "%s : ", strerror(errnum));

	vfprintf(stderr, format, ap);

	fputc('\n',stderr);

	fflush(stderr);

	va_end(ap);
	if (status)
		exit(status);
}
