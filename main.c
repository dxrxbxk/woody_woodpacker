int main(void) {
	__asm__ ("mov $0x1050, %rax");
	__asm__ ("jmp *%rax");
}
