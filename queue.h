#include "queue.c"

que_ptr create();
int push(que_ptr q, void *obj);
void* pop(que_ptr q);
node_ptr pop_all(que_ptr q);
void print_que(que_ptr q);
void destroy(que_ptr q);