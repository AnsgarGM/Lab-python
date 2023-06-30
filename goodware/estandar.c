#include <stdio.h>

int main() {
    int numero;

    // Escritura en la salida estándar
    printf("Escribiendo en la salida estándar...\n");

    // Escritura en el error estándar
    fprintf(stderr, "Escribiendo en el error estándar...\n");

    // Lectura de la entrada estándar
    printf("Ingresa un número: ");
    scanf("%d", &numero);

    // Impresión del número ingresado
    printf("El número ingresado es: %d\n", numero);

    return 0;
}
