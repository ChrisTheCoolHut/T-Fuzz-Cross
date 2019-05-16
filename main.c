#include <stdlib.h>
#include <string.h>

int main(int argc,  char *argv[])
{
	char other_buf[5] = {'\x00'};
	int comp_val = 0x41424344;
	printf("Exploit me!\n");
	read(0, other_buf, 10);

	if(memcmp(other_buf, &comp_val, 4) == 0)
	{
		do_bad_thing();
	}
	if(strstr(other_buf, "fuzz1") != NULL)
	{
		do_bad_thing();
	}
	return 0;
}

void do_bad_thing()
{
	printf("You can do that bad thing!\n");
	char buf[100]  = {'\x00'};
	gets(buf);
}
