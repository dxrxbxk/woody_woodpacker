#include <stdio.h>

void	*singleton(void *addr) {
	static void	*ptr;

	if (addr)
		ptr = addr;
	return (ptr);
}


int main() {

	void	*ptr = singleton(NULL);

	printf("ptr = %p\n", ptr);

	return 0;
}
