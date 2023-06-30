/**
gen_direc.c .- Programa que genera los directorios importantes para realizar los analisis

para compilar

gcc gen_direc.c -o gen 

para ejecutar estatico

./gen 1

para ejecutar dinamico 

./gen 2
*/


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

int main (int argc, char * argv[])
{
    if (argc < 2) 
    {
        perror("Ingrese argumentos\n");
        return 0;
    }
    int flag = atoi(argv[1]);
    
    //Cambiar a ruta de la maquina virtual
    char* InitPath="/home/ruzkn47";

    char* Lab="Lab";
    char* download="Lab/download_malware";
    char* dinamicscripts="Lab/DinScripts";
    char* staticscripts="Lab/StatScripts";
    char* jsonpath="Lab/Json";
    char* logs="Lab/Logs";

    //Comenzando en la ruta de home del usuario 

    if (chdir(InitPath) != 0)
    {
        printf("[X]Problemas para ir a la ruta %s",InitPath);
        return 0;
    }

    //Creando el directorio principal del Laboratorio

    if(mkdir(Lab,0700) != 0)
    {
            perror("[X]Error al crear el directorio principal Lab.\n");
            return 0;
    }   
        
    //Creando los demas directorios

    if(mkdir(download,0700) != 0 || mkdir(jsonpath,0700) !=0 || mkdir(logs,0700) != 0)
    {
            perror("[X]Error al crear los directorios principales del laboratorio\n");
            return 0;
    }  

    //Analisis estatico
    if(flag==1)
        if(mkdir(staticscripts,0700) != 0)
        {
            perror("[X]Error al crear el directorio de los scripts estaticos.\n");
            return 0;
        }   
        
    
    //Analisis dinamico
    if(flag==0)
        if(mkdir(dinamicscripts,0700) != 0)
        {
            perror("[X]Error al crear el directorio de los scripts dinamicos.\n");
            return 0;
        }  

    
    return 1;
}