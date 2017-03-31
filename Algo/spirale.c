#include<stdio.h>
#include<stdlib.h>
#define EOL "\n"
int main(int argc, char *args[]) {
    int N = atoi(args[1]);
    if(N%2==0) {
        printf("Challenge QuarksLAB, determine si une matrice possede un centre ... ou pas"EOL);
        printf("Merci d'entrer un nombre impair :"EOL);
        return 0;
    }

    int n = N/2, N2 = N*N, m = N2/2;
    int r=1, p = m+r, v = 0,  i, j;

/* init matrice */
    int * buffer = (int*) calloc (N2,sizeof(int));
    buffer[m] = v;

    while(r<=n) {
        int
        P1 = m+(N*r)+r,
        P2 = m+(N*r)-r,
        P3 = m-(N*r)-r,
        P4 = m-(N*r)+r;

        while(p < P1) {
            buffer[p] = ++v;
            p += N;
        }

        while(p > P2) {
            buffer[p] = ++v;
            p -= 1;
        }

        while(p > P3) {
            buffer[p] = ++v;
            p -= N;
        }

        while(p <= P4) {
            buffer[p] = ++v;
            p += 1;
        }
        r++;
    }
	
/* print matrice */
    for(i=0;i<N2;i++) {
        if(i%N==0)
            printf(EOL);
        printf(" %2d ", buffer[i]);
    }

    free(buffer);
    return 0;
}
