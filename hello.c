#include <stdio.h>


int main() {

	static int *i;

	printf("%p\n", i);

	return 0;
}
