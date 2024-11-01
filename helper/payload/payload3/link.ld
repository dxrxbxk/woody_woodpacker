ENTRY(_start)

PHDRS
{
  text PT_LOAD FLAGS(5);
}

SECTIONS
{
	. = 0x401000;
	/* change to executable and writable */
	.text : { *(.text) }
}

