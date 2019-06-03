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
#include <sys/mman.h>
#include <sys/select.h>

main(int argc, char* argv[]){

	char *buf = malloc(10000);
    unsigned long byte;
	void *shellcode;
    char *page;
	char stuff[10];
	int secs = 30;
    fd_set fds;
    struct timeval timeout;

	if (argc > 1) {
		secs = atoi(argv[1]);
	}


	shellcode = buf;

    // make it rwx for simplicity
    page = (char*)((long)buf & 0xfffff000);

    if (mprotect(page, 0x10000, PROT_EXEC | PROT_WRITE | PROT_READ))
        err(1, "mprotect failed! ");

	printf("Shellcode loading at: %x.  \n", buf);
    //if (argc > 2) {

	//*buf++ = fgetc(stdin);
	//while ((*buf++ = fgetc(stdin)) != EOF);
    FD_ZERO(&fds);
    FD_SET(0, &fds);
    timeout.tv_sec = 1;

    byte = fgetc(stdin);
    while (byte != 0xffffffff)
    {
        printf(" %x", byte);
        *buf++ = (char)byte;
        byte = fgetc(stdin);
    }

    //read((int)stdin, shellcode, 0x10000);
	printf("Shellcode loaded.  End address: %x.", buf);
	printf("\nWaiting %d seconds before executing...", secs);
	printf("\n");
	sleep(secs);
	printf("  Jumping into shellcode now...", buf);
	goto *shellcode;

}
