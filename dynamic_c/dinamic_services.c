//dinamic_service.c .- programa que realiza el analisis dinamico tomanodo como parametros un json
//Para compilar gcc dinamic_service.c -o dinamic_service -lm -lcjson
//gcc dinamic_services.c -o dinamic_service -lm -lcjson -Wl,-rpath=/usr/local/lib
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
    int loop_exp;
    char static_test[TAM_VALUES];
    char call_sys[TAM_VALUES];
    char lib_sys[TAM_VALUES];
    char lib_sys_time[TAM_VALUES];
    char net_pcap[TAM_VALUES];
    char lsof[TAM_VALUES];
}DatosJSON;

int get_JSON(DatosJSON* datos)
{
    char * ruta="/home/analista/Lab/Json/config.json";
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


    elemento = cJSON_GetObjectItemCaseSensitive(json, "loop_exp");
    if (cJSON_IsNumber(elemento)) {
        datos->loop_exp = elemento->valueint;
    }
   

    //Obteniendo valor sha1
    elemento = cJSON_GetObjectItemCaseSensitive(json, "static_test");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->static_test, elemento->valuestring, sizeof(datos->static_test) - 1);
        datos->static_test[sizeof(datos->static_test)- 1] = '\0';
    }

    //Obteniendo valor sha256
    elemento = cJSON_GetObjectItemCaseSensitive(json, "call_sys");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->call_sys, elemento->valuestring, sizeof(datos->call_sys) - 1);
        datos->call_sys[sizeof(datos->call_sys)- 1] = '\0';
    }


    //Obteniendo valor string
    elemento = cJSON_GetObjectItemCaseSensitive(json, "lib_sys");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->lib_sys, elemento->valuestring, sizeof(datos->lib_sys) - 1);
        datos->lib_sys[sizeof(datos->lib_sys)- 1] = '\0';
    }

    //Obteniendo valor file
    elemento = cJSON_GetObjectItemCaseSensitive(json, "lib_sys_time");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->lib_sys_time, elemento->valuestring, sizeof(datos->lib_sys_time) - 1);
        datos->lib_sys_time[sizeof(datos->lib_sys_time)- 1] = '\0';
    }

    elemento = cJSON_GetObjectItemCaseSensitive(json, "net_pcap");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->net_pcap, elemento->valuestring, sizeof(datos->net_pcap) - 1);
        datos->net_pcap[sizeof(datos->net_pcap)- 1] = '\0';
    }

    elemento = cJSON_GetObjectItemCaseSensitive(json, "lsof");
    if (cJSON_IsString(elemento)) {
        strncpy(datos->lsof, elemento->valuestring, sizeof(datos->lsof) - 1);
        datos->lsof[sizeof(datos->lsof)- 1] = '\0';
    }


    return 0;
}

char * gen_cadena(char *ComName, char* Malware_Name, int x)
{
    time_t currentTime = time(NULL);
    struct tm *localTime = localtime(&currentTime);
    int MAX_BUFFER_SIZE=300;
    char * ruta="/home/analista/Lab/Logs/";
    // Crear un buffer para almacenar la cadena
    char* buffer=malloc(MAX_BUFFER_SIZE);

    // Generar la cadena con el formato "Nommalware_fecha_y_hora.log"
    sprintf(buffer, "%s%s_%s_%04d%02d%02d_%02d%02d%02d_V%d.log",ruta,ComName,Malware_Name,localTime->tm_year + 1900, localTime->tm_mon + 1, localTime->tm_mday, localTime->tm_hour, localTime->tm_min, localTime->tm_sec,x);

    // Imprimir la cadena generada
    //printf("\nCadena generada: %s", buffer);

    return buffer;
}

int exec_command(int opc, char* ComName, char* Malware_Name, int x) {
    const char* malware_path = "/home/analista/Lab/download_malware/";
    FILE* logFile = fopen(gen_cadena(ComName, Malware_Name,x), "w");
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
                sprintf(comando, "sha1sum %s", ruta);
                sprintf(comando, "sha256sum %s", ruta);
                sprintf(comando, "file %s", ruta);
                sprintf(comando, "hexdump -C %s", ruta);
                break;
            case 2:
                sprintf(comando, "strace %s", ruta);
                break;
            case 3:
                sprintf(comando, "ltrace %s", ruta);
                break;
            case 4:
                sprintf(comando, "ltrace -c %s", ruta);
                break;
            case 5:
                sprintf(comando, "./tcpdump %s",ruta);
                break;
            case 6:
                sprintf(comando, "lsof ");
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
    const char* malware_path = "/home/analista/Lab/download_malware/";
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
    const char* malware_path = "/home/analista/Lab/download_malware/";
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


int Close_Firewall()
{
    // Comando para cerrar el firewall utilizando IPTABLES
    const char *IN_DROP = "iptables -P INPUT DROP";
    const char *FOR_DROP = "iptables -P FORWARD DROP";
    const char *OUT_DROP = "iptables -P INPUT DROP";
    // Construir el comando completo con "sudo"
    char comandoCompleto[256];
    snprintf(comandoCompleto, sizeof(comandoCompleto), "sudo %s", IN_DROP);

    // Ejecutar el comando utilizando "system"
    int r1 = system(comandoCompleto);
    snprintf(comandoCompleto, sizeof(comandoCompleto), "sudo %s", FOR_DROP);
    int r2 = system(comandoCompleto);
    snprintf(comandoCompleto, sizeof(comandoCompleto), "sudo %s", OUT_DROP);
    int r3 = system(comandoCompleto);
    // Verificar si el comando se ejecutó correctamente
    if (r1 == -1 || r2 == -1 || r3 == -1) {
        perror("Error al ejecutar el comando IPTABLES");
        return 0;
    } 
    return 1;
}

int OpenFirewall()
{
    // Comando para cerrar el firewall utilizando IPTABLES
    const char *IN_DROP = "iptables -P INPUT ACCEPT";
    const char *FOR_DROP = "iptables -P FORWARD ACCEPT";
    const char *OUT_DROP = "iptables -P INPUT ACCEPT";
    // Construir el comando completo con "sudo"
    char comandoCompleto[256];
    snprintf(comandoCompleto, sizeof(comandoCompleto), "sudo %s", IN_DROP);

    // Ejecutar el comando utilizando "system"
    int r1 = system(comandoCompleto);
    snprintf(comandoCompleto, sizeof(comandoCompleto), "sudo %s", FOR_DROP);
    int r2 = system(comandoCompleto);
    snprintf(comandoCompleto, sizeof(comandoCompleto), "sudo %s", OUT_DROP);
    int r3 = system(comandoCompleto);
    // Verificar si el comando se ejecutó correctamente
    if (r1 == -1 || r2 == -1 || r3 == -1) {
        perror("Error al ejecutar el comando IPTABLES");
        return 0;
    } 
    return 1;
}


int main (int argc , char * argv[])
{
    DatosJSON datos;
    int x;
    printf("\n[+]Iniciando Analisis..");
    printf("\n[+]Obteniendo datos del Json");
    if (get_JSON(&datos) == 1)
    {
        printf("\n[X]Error al leer datos del Json");
        return 1;
    }
    printf("\nMostrando Datos del JSON: ");

    printf("\nNombre Malware: %s",datos.MalwareName);
    printf("\nStatic test OPC: %s",datos.static_test);
    printf("\nLoop experiment OPC: %d",datos.loop_exp);
    printf("\nCall system OPC: %s",datos.call_sys);
    printf("\nLibrary system OPC: %s",datos.lib_sys);
    printf("\nLibrary System Time OPC: %s",datos.lib_sys_time);
    printf("\nNetwork Monitor OPC: %s",datos.net_pcap);
    printf("\nLsof OPC: %s",datos.lsof);

    
    if(validador_unpacked(datos.MalwareName) == 0)
        if(unpack(datos.MalwareName)==0)
        {
             printf("\n[-]No se desempaqueto correctamente el archivo ");
             return 0;
        }  

    if (Close_Firewall() == 0)
    {
        perror("\n[-]Error al cerrar el firewall");
        return 0;
    }    


    printf("\n[+]Analisis estatico Comenzando");

    for(x=1;x<datos.loop_exp+1;x++)
    {

    if(strcmp(datos.static_test,"TRUE") == 0)
        if(exec_command(1,"static_test",datos.MalwareName,x)==0)
            printf("\n[X]Problema con el static test log");

    if(strcmp(datos.call_sys,"TRUE") == 0)
        if(exec_command(2,"call_sys",datos.MalwareName,x)==0)
            printf("\n[X]Problema con el call sys log");

    if(strcmp(datos.lib_sys,"TRUE") == 0)
        if(exec_command(3,"lib_sys",datos.MalwareName,x)==0)
            printf("\n[X]Problema con el log MD5");

    if(strcmp(datos.lib_sys_time,"TRUE") == 0)
        if(exec_command(4,"lib_sys_time",datos.MalwareName,x)==0)
            printf("\n[X]Problema con el log de STRING");

    if(strcmp(datos.net_pcap,"TRUE") == 0)
        if(exec_command(5,"net_pcap",datos.MalwareName,x)==0)
            printf("\n[X]Problema con el log del net_pcap");

    if(strcmp(datos.lsof,"TRUE") == 0)
        if(exec_command(6,"lsof",datos.MalwareName,x)==0)
            printf("\n[X]Problema con el log del lsof");

    }

    
    if ( OpenFirewall()== 0)
        perror("\n[-] Error al abrir el Firewall ");
    //printf("[+]Analisis Estatico Finalizado");
    return 0;
}
