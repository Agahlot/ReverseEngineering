#include<time.h>
int main() {
	int antidbg = clock();
	/*
	 // Routine du Programme � prot�ge
	 */
	if (clock() - antidbg > 100) {
		printf("Anti-Debugging Protection");
		return 0x1;
	}
}
