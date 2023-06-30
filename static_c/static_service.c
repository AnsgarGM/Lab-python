//static_service.c .- programa que realiza el analisis estatico tomanodo como parametros un json
//Para compilar gcc static_service.c -o static_service -lm -lcjson
//gcc static_service.c -o static_service -lm -lcjson -Wl,-rpath=/usr/local/lib
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <cjson/cJSON.h>

#define TAM_MALWARE 100
#define TAM_VALUES 10
typedef struct {
    char MalwareName[TAM_MALWARE];
    char md5opc[TAM_VALUES];
    char sha1opc[TAM_VALUES];
    char sha256opc[TAM_VALUES];
    char str[TAM_VALUES];
    char fileopc[TAM_VALUES];
    char binheaderopc[TAM_VALUES];
    char symopc[TAM_VALUES];
    char ehframeopc[TAM_VALUES];
    char callsysopc[TAM_VALUES];
    char libopc[TAM_VALUES];
    char disopc[TAM_VALUES];
    char hexadump[TAM_VALUES];
    char exiftool[TAM_VALUES];
}DatosJSON;


int get_JSON(DatosJSON* datos)
{
    char * ruta="/home/ruzkn47/Documents/Malware_lab/ProyectoFinal/Final_scripts/Lab/Json/configstatic.json";
    FILE *archivo = fopen(ruta, "r");
    if (archivo == NULL) {
        perror("Error al abrir el archivo JSON");
        return 1;
    }
     // Leer el contenido del archivo
    fseek(archivo, 0, SEEK_END);
    long tamano = ftell(archivo);
    rewind(archivo);
    char *contenido = malloc(tamano + 1);
    fread(contenido, 1, tamano, archivo);
    fclose(archivo);
    contenido[tamano] = '\0';

    // Parsear el contenido JSON
    cJSON *json = cJSON_Parse(contenido);
    free(contenido);


    if (json == NULL) {
        const char *error = cJSON_GetErrorPtr();
        if (error != NULL) {
            fprintf(stderr, "Error al parsear JSON: %s\n", error);
        }
        return 1;
    }

    //Obteniendo nombre del malware
    cJSON *elemento = cJSON_GetObjectItemCaseSensitive(json, "malware_name");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->MalwareName, elemento->valuestring, sizeof(datos->MalwareName) - 1);
        datos->MalwareName[sizeof(datos->MalwareName)- 1] = '\0';
    }

    //Obteniendo valor md5
    elemento = cJSON_GetObjectItemCaseSensitive(json, "md5opc");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->md5opc, elemento->valuestring, sizeof(datos->md5opc) - 1);
        datos->md5opc[sizeof(datos->md5opc)- 1] = '\0';
    }


    //Obteniendo valor sha1
    elemento = cJSON_GetObjectItemCaseSensitive(json, "sha1opc");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->sha1opc, elemento->valuestring, sizeof(datos->sha1opc) - 1);
        datos->sha1opc[sizeof(datos->sha1opc)- 1] = '\0';
    }

    //Obteniendo valor sha256
    elemento = cJSON_GetObjectItemCaseSensitive(json, "sha256opc");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->sha256opc, elemento->valuestring, sizeof(datos->sha256opc) - 1);
        datos->sha256opc[sizeof(datos->sha256opc)- 1] = '\0';
    }


    //Obteniendo valor string
    elemento = cJSON_GetObjectItemCaseSensitive(json, "strings");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->str, elemento->valuestring, sizeof(datos->str) - 1);
        datos->str[sizeof(datos->str)- 1] = '\0';
    }

    //Obteniendo valor file
    elemento = cJSON_GetObjectItemCaseSensitive(json, "fileopc");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->fileopc, elemento->valuestring, sizeof(datos->fileopc) - 1);
        datos->fileopc[sizeof(datos->fileopc)- 1] = '\0';
    }


    //Obteniendo valor cabecera de binario
    elemento = cJSON_GetObjectItemCaseSensitive(json, "binheaderopc");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->binheaderopc, elemento->valuestring, sizeof(datos->binheaderopc) - 1);
        datos->binheaderopc[sizeof(datos->binheaderopc)- 1] = '\0';
    }


    //Obteniendo valor tabla de simbolos
    elemento = cJSON_GetObjectItemCaseSensitive(json, "symopc");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->symopc, elemento->valuestring, sizeof(datos->symopc) - 1);
        datos->symopc[sizeof(datos->symopc)- 1] = '\0';
    }

    //Obteniendo valor eh_frame 
    elemento = cJSON_GetObjectItemCaseSensitive(json, "eh_frameopc");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->ehframeopc, elemento->valuestring, sizeof(datos->ehframeopc) - 1);
        datos->ehframeopc[sizeof(datos->ehframeopc)- 1] = '\0';
    }

    //Obteniendo valor call system  
    elemento = cJSON_GetObjectItemCaseSensitive(json, "callsysopc");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->callsysopc, elemento->valuestring, sizeof(datos->callsysopc) - 1);
        datos->callsysopc[sizeof(datos->callsysopc)- 1] = '\0';
    }
    
    //Obteniendo valor libopc  
    elemento = cJSON_GetObjectItemCaseSensitive(json, "libopc");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->libopc, elemento->valuestring, sizeof(datos->libopc) - 1);
        datos->libopc[sizeof(datos->libopc)- 1] = '\0';
    }

    //Obteniendo valor disambler  
    elemento = cJSON_GetObjectItemCaseSensitive(json, "disopc");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->disopc, elemento->valuestring, sizeof(datos->disopc) - 1);
        datos->disopc[sizeof(datos->disopc)- 1] = '\0';
    }
    
    //Obteniendo valor hexadump
    elemento = cJSON_GetObjectItemCaseSensitive(json, "hexadump");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->hexadump, elemento->valuestring, sizeof(datos->hexadump) - 1);
        datos->hexadump[sizeof(datos->hexadump)- 1] = '\0';
    }

    elemento = cJSON_GetObjectItemCaseSensitive(json, "exiftool");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->hexadump, elemento->valuestring, sizeof(datos->hexadump) - 1);
        datos->hexadump[sizeof(datos->hexadump)- 1] = '\0';
    }
    return 0;
}

char * gen_cadena(char *ComName, char* Malware_Name)
{
    time_t currentTime = time(NULL);
    struct tm *localTime = localtime(&currentTime);
    int MAX_BUFFER_SIZE=300;
    char * ruta="/home/ruzkn47/Documents/Malware_lab/ProyectoFinal/Final_scripts/Lab/Logs/";
    // Crear un buffer para almacenar la cadena
    char* buffer=malloc(MAX_BUFFER_SIZE);

    // Generar la cadena con el formato "Nommalware_fecha_y_hora.log"
    sprintf(buffer, "%s%s_%s_%04d%02d%02d_%02d%02d%02d.log",ruta,ComName,Malware_Name,localTime->tm_year + 1900, localTime->tm_mon + 1, localTime->tm_mday, localTime->tm_hour, localTime->tm_min, localTime->tm_sec);

    // Imprimir la cadena generada
    //printf("\nCadena generada: %s", buffer);

    return buffer;
}

int exec_command(int opc, char* ComName, char* Malware_Name) {
    const char* malware_path = "/home/ruzkn47/Documents/Malware_lab/ProyectoFinal/Final_scripts/Lab/download_malware/";
    FILE* logFile = fopen(gen_cadena(ComName, Malware_Name), "w");
    char ruta[300];
    sprintf(ruta, "%s%s", malware_path, Malware_Name);

    // Redirigir la salida estándar hacia el archivo de log
    //printf("\nRuta de malware: %s", ruta);

    if (logFile != NULL) {
        int fd = fileno(logFile);
        dup2(fd, STDOUT_FILENO);

        // Ejecutar la opción del comando a usar
        char comando[500];  // Definir un buffer para almacenar el comando completo
        switch (opc) {
            case 1:
                sprintf(comando, "md5sum %s", ruta);
                break;
            case 2:
                sprintf(comando, "sha1sum %s", ruta);
                break;
            case 3:
                sprintf(comando, "sha256sum %s", ruta);
                break;
            case 4:
                sprintf(comando, "strings %s", ruta);
                break;
            case 5:
                sprintf(comando, "file %s", ruta);
                break;
            case 6:
                sprintf(comando, "readelf -h %s && readelf -l %s", ruta, ruta);
                break;
            case 7:
                sprintf(comando, "readelf -s %s", ruta);
                break;
            case 8:
                sprintf(comando, "readelf -w --debug-dump %s", ruta);
                break;
            case 9:
                sprintf(comando, "readelf -r %s", ruta);
                break;
            case 10:
                sprintf(comando, "ldd %s", ruta);
                break;
            case 11:
                sprintf(comando, "objdump -d %s", ruta);
                break;
            case 12:
                sprintf(comando, "hexdump -C %s", ruta);
                break;
            case 13:
                sprintf(comando, "exiftool %s", ruta);
                break;
            default:
                perror("\nError al ejecutar el comando ");
        }

        // Ejecutar el comando usando system
        system(comando);

        fclose(logFile);
    } else {
        perror("Error al abrir el archivo de log");
        return 0;
    }

    return 1;
}


int validador_unpacked(char* Malware_Name)
{
    const char* malware_path = "/home/ruzkn47/Documents/Malware_lab/ProyectoFinal/Final_scripts/Lab/download_malware/";
    char ruta[300];
    sprintf(ruta, "%s%s", malware_path, Malware_Name);

    // Construir el comando para verificar el estado de desempaquetado con UPX
    char comando[200];
    sprintf(comando, "upx -t %s", ruta);

    // Ejecutar el comando utilizando system
    int resultado = system(comando);

    // Verificar el código de retorno
    if (resultado == 0) {
        printf("El archivo está desempaquetado.\n");
        return 0;
    }
    return 1;
}

int unpack(char* Malware_Name)
{
    const char* malware_path = "/home/ruzkn47/Documents/Malware_lab/ProyectoFinal/Final_scripts/Lab/download_malware/";
    char ruta[300];
    sprintf(ruta, "%s%s", malware_path, Malware_Name);

    // Construir el comando para verificar el estado de desempaquetado con UPX
    char comando[200];
    sprintf(comando, "upx -d %s", ruta);

    // Ejecutar el comando utilizando system
    int resultado = system(comando);

    // Verificar el código de retorno
    if (resultado == 0) {
        printf("[+]El archivo se desempaqueto correctamente.\n");
        return 0;
    }
    return 1;
}


int main (int argc , char * argv[])
{
    DatosJSON datos;
    printf("\n[+]Iniciando Analisis..");
    printf("\n[+]Obteniendo datos del Json");
    if (get_JSON(&datos) == 1)
    {
        printf("\n[X]Error al leer datos del Json");
        return 1;
    }
    printf("\nMostrando Datos del JSON: ");

    printf("\nNombre Malware: %s",datos.MalwareName);
    printf("\nMD5SUM OPC: %s",datos.md5opc);
    printf("\nSHA1SUM OPC: %s",datos.sha1opc);
    printf("\nSHA256SUM OPC: %s",datos.sha256opc);
    printf("\nString OPC: %s",datos.str);
    printf("\nFILE OPC: %s",datos.fileopc);
    printf("\nBINARY HEADER OPC: %s",datos.binheaderopc);
    printf("\nTabla de Simbolos OPC: %s",datos.symopc);
    printf("\neh_frame OPC: %s",datos.ehframeopc);
    printf("\nLlamadas al sistema OPC: %s",datos.callsysopc);
    printf("\nlibreria OPC: %s",datos.libopc);
    printf("\nDesemblador OPC: %s",datos.disopc);

    
    if(validador_unpacked(datos.MalwareName) == 0)
        if(unpack(datos.MalwareName)==0)
        {
             printf("\n[-]No se desempaqueto correctamente el archivo ");
             return 0;
        }  


    printf("\n[+]Analisis estatico Comenzando");

    if(strcmp(datos.md5opc,"TRUE") == 0)
        if(exec_command(1,"MD5",datos.MalwareName)==0)
            printf("\n[X]Problema con el log MD5");

    if(strcmp(datos.sha1opc,"TRUE") == 0)
        if(exec_command(2,"SHA1",datos.MalwareName)==0)
            printf("\n[X]Problema con el log SHA1");

    if(strcmp(datos.sha256opc,"TRUE") == 0)
        if(exec_command(3,"SHA256",datos.MalwareName)==0)
            printf("\n[X]Problema con el log MD5");

    if(strcmp(datos.str,"TRUE") == 0)
        if(exec_command(4,"STRING",datos.MalwareName)==0)
            printf("\n[X]Problema con el log de STRING");

    if(strcmp(datos.fileopc,"TRUE") == 0)
        if(exec_command(5,"FILE",datos.MalwareName)==0)
            printf("\n[X]Problema con el log del FILE");

    if(strcmp(datos.binheaderopc,"TRUE") == 0)
        if(exec_command(6,"BINHEAD",datos.MalwareName)==0)
            printf("\n[X]Problema con el log del header del binario");

    if(strcmp(datos.symopc,"TRUE") == 0)
        if(exec_command(7,"SYMB",datos.MalwareName)==0)
            printf("\n[X]Problema con el log de tabla de simbolos");

    if(strcmp(datos.ehframeopc,"TRUE") == 0)
        if(exec_command(8,"EHFRAM",datos.MalwareName)==0)
            printf("\n[X]Problema con el log eh_frame");

    if(strcmp(datos.callsysopc,"TRUE") == 0)
        if(exec_command(9,"CALLSYS",datos.MalwareName)==0)
            printf("\n[X]Problema con el log de llamadas al sistema");

    if(strcmp(datos.libopc,"TRUE") == 0)
        if(exec_command(10,"LIB",datos.MalwareName)==0)
            printf("\n[X]Problema con el log de librerias");

    if(strcmp(datos.disopc,"TRUE") == 0)
        if(exec_command(11,"DIS",datos.MalwareName)==0)
            printf("\n[X]Problema con el log del desemsamblador");
    
    if(strcmp(datos.hexadump,"TRUE") == 0)
        if(exec_command(12,"HEX",datos.MalwareName)==0)
            printf("\n[X]Problema con el log del hexadump");

    if(strcmp(datos.exiftool,"TRUE") == 0)
        if(exec_command(13,"EXIFT",datos.MalwareName)==0)
            printf("\n[X]Problema con el log del exiftool");    
    //printf("[+]Analisis Estatico Finalizado");
    return 0;
}
