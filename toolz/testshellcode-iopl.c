/******************************************************************************************************8888
 * testshellcode is intended to simply accept in shellcode on stdin, and jump into it.  This should help in 
 * debugging shellcode, testing it's functionality, or simply eliminate shellcode from troubleshooting
 *
 * I used to maintain a hacked up tool to disassemble shellcode (since there are no ELF headers, etc...) but 
 * have found that ndisasm (from binutils) does a great job.
 ***********************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

main(int argc, char* argv[]){

	char *buf = malloc(10000);
	void *shellcode;
	char stuff[10];
	int secs = 30;

	if (argc > 1) {
		secs = atoi(argv[1]);
	}
        if(iopl(3) == -1) {
                fprintf(stderr, "error: this program needs root privileges\n");
                return(-1);
        }

	shellcode = buf;
	printf("Shellcode loading at: %x.  \n", buf);
	*buf++ = fgetc(stdin);
	while ((*buf++ = fgetc(stdin)) != EOF);
	printf("Shellcode loaded.  End address: %x.", buf);
	printf("\nWaiting %d seconds before executing...", secs);
	printf("\n");
	sleep(secs);
	printf("  Jumping into shellcode now...", buf);
	goto *shellcode;

}
