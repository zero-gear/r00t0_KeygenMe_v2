### r00t0 KeygenMe v2 [[Source]](https://forum.tuts4you.com/topic/39969-r00t0-keygenme-v2/) solution:

##### Manual Unpacking of UPX
Described [here](https://securityxploded.com/unpackingupx.php). x64dbg & scylla are your friends.

##### Explore unpacked program control flow
Using cross-references to strings "_Registration name:_", "_Registration Serial:_", "_\nRegistration Succeeded_", "_\nRegistration Failed_"
i located print function(VA 0x007d6f40) and all calls to it. Single stepping between print("_Registration name:_") and print("_Registration Serial:_")
 i have empirically defined wrapper function that get input from terminal(VA 0x007D7C70). Ok, we have narrow range to analyze :
from call to get input name at 0x0061641C to call of print("_\nRegistration Failed_") at 0x006FF521 or call of print("_\nRegistrationSucceeded_") at 0x006EFCE1.

Lets go.

Code analysis is hardened with innumerable absolute jump instructions, that interleave code, so called "_spaghetti-code_".
![](https://github.com/smart-rabbit/r00t0_KeygenMe_v2/blob/master/images/spaghetti-code.png)
Between each asm instruction, there 30-80 trash jump instructions.

x64dbg trace command `TraceIntoConditional 1:[cip]!=0xe9 && 1:[cip]!=0xeb`, which trace until meet not jump instruction save us tons of hours.
Tracing such way, we stop only at usefull instructions and set software breakpoints on them. Now we can switch to x32dbg 'Breakpoints' tab, and overview
all instruction that validate _name:serial_ pair.
![](https://github.com/smart-rabbit/r00t0_KeygenMe_v2/blob/master/images/pure_validation_code.png)

**Validation algorithm**:

_0 step_: get name and serial from input
```C
char name[0x22+1] = {0};
char input_serial[32+1+8+1] = {0};
puts("Registration name:")
fgets (name, 0x22+1, stdin);
puts("Registration Serial:")
fgets (name, 41+1, stdin);
```
_1st step_: check name length
```python
2 < name <= 0x22
```
_2nd step_: get [CPUID](https://en.wikipedia.org/wiki/CPUID#EAX=0:_Get_vendor_ID_(including_EAX=1:_Get_CPUID)) 
```C
uint32_t cpuid[4] = {0};
__cpuid(cpuid, 0);
```
_3d  step_: get 4-byte hash from name 
```C
uint32_t Nhash = 0;
for (size_t i = 0; i < strlen(name); i++) {
	Nhash += name[i];
	Nhash ^= 0x00ABCDEF;
	Nhash = Nhash + (cpuid[0] ^ Nhash);
}
```
_4th step_: get valid serial from name and CPUID
```C
char derived_serial[32 + 1 + 8] = {0};
sprintf(derived_serial, "%X%X%X%X-%X", cpuid[0], cpuid[1], cpuid[2], cpuid[3], Nhash);
```
_5th step_: compare input serial and serial derived from name and CPUID
```C
if (strcmp(input_serial, derived_serial) == 0){
    puts("\nRegistration Succeeded");
} else {
    puts("\nRegistration Failed");
}
```


Keygen is simply made from above code:
```C
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
```
