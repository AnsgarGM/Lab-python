#include <stdio.h>
int main(){
    int cont = 0;
    for( int i = 0; i < 100; i++ ){
        if( i % 3 == 0 ){
            cont += i * i;
        }
    }
    return 0;
}