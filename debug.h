#ifndef DEBUG_H_
#define DEBUG_H_

#define WARN(...) do {                                  \
	fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__);                   \
	fputc('\n', stderr);                            \
} while(0);

#define DIE(...) do {       \
	WARN(__VA_ARGS__);  \
	exit(EXIT_FAILURE); \
} while (0)

#endif
