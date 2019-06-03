#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>

int
main(int argc, char *argv[])
{
    char buf[10000];
    char buf2[10000];

    while (fgets(buf, sizeof(buf), stdin)) {
	char *p = buf;

	char last = 0;
	while (*p) {
	    int l = strcspn(p, " \n\t()\"\'");

	    if (last)
		printf("%c", last);
	    last = p[l];
	    p[l] = 0;

	    buf2[0] = 0;
	    if (p[0] && !UnDecorateSymbolName(p, buf2, sizeof(buf2), UNDNAME_COMPLETE)) {
		printf("%s", p);
	    } else
		printf("%s", buf2);
	    p += l + 1;
	}
	if (last)
	    printf("%c", last);
    }
    return 0;
}

