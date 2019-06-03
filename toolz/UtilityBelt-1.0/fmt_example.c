#include <stdio.h>

int main(){
	char string[7] = "sample";
	int A = -72;
	unsigned int B = 31337;
	int count_one, count_two;

	// Example of printing with diff format string
	printf("[A] Dec: %d, Hex: %x, Unsigned:%u\n", A, A, A);
	printf("[B] Dec: %d, Hex: %x, Unsigned:%u\n", B, B, B);
	printf("[field width on B] 3: '%3u', 10: '%10u', '%08u'\n", B, B, B);
	printf("string] %s  Address %08x\n", string, string);
	printf("count_one is located at: %08x\n", &count_one);
	printf("count_two is located at: %08x\n", &count_two);

	//Example opf a %n format string
	printf("The number of bytes written up to this point X%n is being stored in count_one, and the bumber of bytes up to here X%n is being stored in count_two.\n", &count_one, &count_two);

	printf("count_one: %d\n", count_one);
	printf("count_two: %d\n", count_two);

	//Stack example
	printf("A is %d and is at %08x.  B is %u and is at %08x.\n", A, &A, B, &B);

	exit(0);
}
