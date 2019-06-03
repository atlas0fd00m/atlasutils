/******************************************************************************************************8888
 * testshellcode is intended to simply accept in shellcode on stdin, and jump into it.  This should help in
 * debugging shellcode, testing it's functionality, or simply eliminate shellcode from troubleshooting
 *
 * I used to maintain a hacked up tool to disassemble shellcode (since there are no ELF headers, etc...) but
 * have found that ndisasm (from binutils) does a great job.
 ***********************************************************************************************************/
#define BUFSIZE 10000

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/mman.h>

int setup(unsigned short port)
{
        char   myname[120];
        int    s;
        struct sockaddr_in sa;
        struct hostent *hp;

        memset(&sa, 0, sizeof(struct sockaddr_in));
        gethostname(myname, 120);
        hp= gethostbyname(myname);
        if (hp == NULL)
                return(-1);
        sa.sin_family= hp->h_addrtype;
        sa.sin_port= htons(port);
        if ((s= socket(AF_INET, SOCK_STREAM, 0)) < 0)
                return(-1);
        if (bind(s,(struct sockaddr *)&sa,sizeof(struct sockaddr_in)) < 0) {
                close(s);
                return(-1);
        }
        listen(s, 100);
        return(s);
}


main(int argc, char* argv[]){

        char *buf = malloc(BUFSIZE);
        void *shellcode;
        char stuff[10];
        int secs = 30;
        int port = 12345;
        int s, as, count;

        if (argc > 2) {
                port = atoi(argv[1]);
                secs = atoi(argv[2]);
        } else if (argc > 1) {
                port = atoi(argv[1]);
        }

        shellcode = buf;
        mprotect(shellcode & 0xfffff000, BUFSIZE, PROT_EXEC | PROT_WRITE | PROT_READ);

        printf("Shellcode loading at: %x.  \n", buf);
        //*buf++ = fgetc(stdin);
        //while ((*buf++ = fgetc(stdin)) != EOF);
        s = setup(port);
        if ((as = accept(s,NULL,NULL)) < 0)
                return(-1);

        count = read(as, buf, BUFSIZE);

        printf("Shellcode loaded.  End address: %x.", buf + count);
        printf("\nWaiting %d seconds before executing...", secs);
        printf("\n");
        sleep(secs);
        printf("  Jumping into shellcode now...", buf);
        goto *shellcode;

}
