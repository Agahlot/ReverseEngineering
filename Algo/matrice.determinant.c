#include<stdio.h>
#include<stdlib.h>

int main() {
    int m,n,i,j,x, det=0;
    printf("M(m,n)\n");
    printf("m = ");
    scanf("%d", &m);
    printf("n = ");
    scanf("%d", &n);
    // --------------------------------------
    int **matrice = (int **) malloc(sizeof(int)*m);
    for(i=0;i<m;i++) {
                     matrice[i] = (int *) malloc(sizeof(int)*n);
                     for(j=0; j<n; j++) {
                              scanf("%d", &matrice[i][j]);
                     }
    }
    // --------------------------------------
    for(i=0;i<m;i++) {
                     int foo=1;
                     for(j=0;j<m;j++) {
                                      foo= foo * matrice[(j)%m][(j+i)%m];
                     }
                     det = det + foo;
    }
    for(x=0;x<m;x++) {
                     int bar=1;
                     for(i=0,j=m-1;i<m,j>-1;i++,j--) {
                                      bar= bar * matrice[(i+x)%m][(j+x)%m];
                     }
                     det = det - bar;
    }
    free(matrice);
    // --------------------------------------
    printf("det = %d", det);
    system("pause");
    return 0;
}
