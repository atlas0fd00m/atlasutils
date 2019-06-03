#include <stdio.h>

main(int argc, char **argv){
 fprintf(stdout, "\nSTDIN: \t\t0x%x",stdin);
 fprintf(stdout, "\nSTDOUT:\t\t0x%x",stdout);
 fprintf(stdout, "\nSTDERR:\t\t0x%x\n\n",stderr);
}
