// segfaults
//
#define NULL ((void *)0)
int	main(void)
{
	char	*str = NULL;

	str[0] = 'a';
	return (0);
}
