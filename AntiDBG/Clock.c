#include<time.h>
int main() {
	int antidbg = clock();
	/*
	 // Routine du Programme à protége
	 */
	if (clock() - antidbg > 100) {
		printf("Anti-Debugging Protection");
		return 0x1;
	}
}
