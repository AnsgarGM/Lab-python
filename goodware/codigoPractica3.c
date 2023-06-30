#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
//Funcion que valida si se esta ejecutando en VMware
//Valida que exista la cadena VMware en los controladores 
int VMwareValidador() {
    FILE *fp = fopen("/proc/scsi/scsi", "r");
    if (fp != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), fp) != NULL) {
            if (strstr(line, "VMware")) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }
    return 0;
}
//Funcion que valida si se esta ejecutando en VirtualBox
//Esta funcion utiliza el ensamblado de Intel para obtener la info de la CPU, para validar las cadenas de identificacion de la CPU del vendedor y la marca.
int VirtualBoxValidator()
{
	char cpu_vendor[13], cpu_brand[49], virtualbox[8] = "Virtual";
    int eax = 0x40000000;
    __asm__(
        "cpuid"
        : "=a"(eax),
          "=b"(*(int *)(cpu_vendor)),
          "=c"(*(int *)(cpu_brand)),
          "=d"(*(int *)(cpu_brand + 16))
        : "a"(eax)
    );
    cpu_vendor[12] = '\0';
    cpu_brand[48] = '\0';
    if (strstr(cpu_brand, virtualbox) != NULL) {
        printf("[+]Está corriendo en VirtualBox\n");
		return 1;
    } else {
        printf("[-]No está corriendo en VirtualBox\n");
    }
    return 0;
}

//Funcion que valida si esta en un entorno de ESXI 
// valida que los archivos y directorios se encuentren. uname, vmware, vmmon.

int ESXiValidador() {
    if (access("/sbin/uname", F_OK) != -1 &&
        access("/usr/lib/vmware", F_OK) != -1 &&
        access("/dev/vmmon", F_OK) != -1) {
        return 1;
    }
    return 0;
}

//Funcion que obtiene la MAC de una interfaz en especifico 
// Compara los 2 primeros bits de la MAC para ver si es multicast y local de administrador.
// Ya que las computadoras fisicas sus MAC en sus primeros 3 bits llevan la marca de la interfaz para identificarlas.

int VirtualMACValidador(const char * interfaz){
	struct ifreq ifr;
    int sockfd;

    // Abrir un socket de tipo AF_INET para obtener información de la interfaz de red
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("Error al abrir el socket");
        exit(1);
    }

    // Establecer el nombre de la interfaz de red de la que se desea obtener la dirección MAC
    strcpy(ifr.ifr_name, interfaz); // Reemplaza "eth0" con el nombre de la interfaz deseada

    // Obtener la dirección MAC
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("Error al obtener la dirección MAC");
        close(sockfd);
        exit(1);
    }

    // Mostrar la dirección MAC en formato hexadecimal
    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    printf("Dirección MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	
	//Verifica el bit de Multicast
	if (mac[0] & 0x01) {
        return 1;
    }

    // Verificar el bit de Local Administration
    if (mac[0] & 0x02) {
        return 1;
    }
    // Cerrar el socket
    close(sockfd);
	return 0;
}


//Funcion que obtiene las interfaces de red de una maquina.
int getNetInt()
{
	struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    // Obtener la lista de interfaces de red
    if (getifaddrs(&ifaddr) == -1) {
        perror("Error al obtener las interfaces de red");
        exit(1);
    }

    // Recorrer la lista de interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        family = ifa->ifa_addr->sa_family;

        // Filtrar solo las interfaces de red IPv4 y IPv6
        if (family == AF_INET || family == AF_INET6) {
            // Obtener el nombre de la interfaz
            printf("Nombre de la interfaz: %s\n", ifa->ifa_name);
			// Obtener la dirección IP asociada a la interfaz
            s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("Error al obtener la dirección IP: %s\n", gai_strerror(s));
                exit(1);
            }
			
			printf("Dirección IP: %s\n", host);
			
			if (VirtualMACValidador(ifa->ifa_name) == 1)
				return 1;  
        }
    }

    // Liberar la memoria asignada por getifaddrs
    freeifaddrs(ifaddr);

    return 0;
}



int main(void) {
	
	
    printf("[+]Comenzando a validar tipo de ambiente de ejecucion.");
	if (ESXiValidador()== 1)
	{
		printf("[+]Se encuentra en un ambiente virtual de ESXI");
		return 1;
	}
	else if (VirtualBoxValidator() == 1 )
	{
		return 1;
	}
	else if (VMwareValidador() == 1)
	{
		printf("[+]Se encuentra en un ambiente virtual de VMware");
		return 1;
	}
	else if ( getNetInt() == 1)
	{
		printf("[+]Se encuentra en un ambiente virtual por su MAC");
		return 1;
	}
	else
	{
		printf("[-]Es una maquina fisica");
		return 0;
	}
	
}
