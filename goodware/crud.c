#include <stdio.h>

void crear_archivo(char* nombre) {
    FILE *f = fopen(nombre, "w");
    if (f == NULL) {
        printf("Error al abrir el archivo!\n");
        return;
    }
    fclose(f);
}

void escribir_archivo(char* nombre, char* contenido) {
    FILE *f = fopen(nombre, "w");
    if (f == NULL) {
        printf("Error al abrir el archivo!\n");
        return;
    }
    fprintf(f, "%s", contenido);
    fclose(f);
}

void leer_archivo(char* nombre) {
    char c;
    FILE *f = fopen(nombre, "r");
    if (f == NULL) {
        printf("Error al abrir el archivo!\n");
        return;
    }
    while ((c = getc(f)) != EOF)
        putchar(c);
    fclose(f);
}

void borrar_archivo(char* nombre) {
    if (remove(nombre) == 0)
        printf("El archivo ha sido borrado exitosamente\n");
    else
        printf("Error al borrar el archivo\n");
}

int main() {
    crear_archivo("test.txt");
    escribir_archivo("test.txt", "Hola, Mundo!");
    leer_archivo("test.txt");
    borrar_archivo("test.txt");
    return 0;
}

