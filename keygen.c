#include <stdio.h>
#include <string.h>
#include <stdint.h>

char * name;
uint32_t Nhash = 0;
uint32_t cpuid[4];
char serial[2*16 + 1 + 2*4];

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("[!] Usage: keygen.exe name\n");
		return 1;
	}
	name = argv[1];
	if (strlen(name) <= 2) {
		printf("[!] Name is too short. It`s length should be minimum 3 chars.\n");
		return 2;
	}
	if (strlen(name) > 0x22) {
		printf("[!] Name is too long. It`s length should be maximum 34 chars.\n");
		return 2;
	}
	printf("Provided name : %s\n", name);

	__cpuid(cpuid, 0);

	for (size_t i = 0; i < strlen(name); i++) {
		Nhash += name[i];
		Nhash ^= 0x00ABCDEF;
		Nhash = Nhash + (cpuid[0] ^ Nhash);
	}

	sprintf(serial, "%X%X%X%X-%X", cpuid[0], cpuid[1], cpuid[2], cpuid[3], Nhash);
	printf("Your serial : %s\n", serial);

	return 0;
}