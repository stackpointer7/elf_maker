#include <stdio.h>
#include <string.h>
#define FILESZ 96
#define MEMSZ 104
#define ERROR(...) {\
	puts(__VA_ARGS__);\
	return -1;\
}
int main(int argc, char **argv) {
	if (argc != 3)
		ERROR("please enter a shellcode file and an output file!")
	unsigned char header[] = "\x7F\x45\x4C\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3E\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x78\x00\x00\x00\x00\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00";
	FILE *shellcode = fopen(argv[1], "rb");
	if (!shellcode)
		ERROR("please make sure the shellcode file is a valid file!")	
	fseek(shellcode, 0, SEEK_END);
	const size_t shell_size = ftell(shellcode);
	rewind(shellcode);
	unsigned char buf[shell_size];
	fread(buf, shell_size, 1, shellcode);
	fclose(shellcode);
	FILE *output = fopen(argv[2], "wb");
	if (!output)
		ERROR("please make sure the output file is able to be written to!")
	memcpy(header + FILESZ, &shell_size, sizeof(size_t));
	memcpy(header + MEMSZ, &shell_size, sizeof(size_t));
	fwrite(header, sizeof(header) - 1, 1, output);
	fwrite(buf, shell_size, 1, output);
	fclose(output);
}
