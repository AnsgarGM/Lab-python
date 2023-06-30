#!/bin/bash
#Script ejecutado con VM_func.sh 

### Ruta principales para el laboratorio


##Variables 
HOSTNAME=$(hostname)
VMPASSWORD="123456"

echo "[+]Comenzando con la configuracion inicial $HOSTNAME"
echo "[+]Creando Ruta Principal del laboratorio"

mkdir $LAB

#CREACION DE CARPETAS CON PROGRAMACION 
#USAR PROGRAMA EN C para generar las carpetas



if [[ $HOSTNAME == *dinamico ]]; then
        echo "[+]Creando Directorios para Maquina Virtual Dinamica"
      
        ./gen 2

        echo $VMPASSWORD | sudo -S apt-get update -y 
        echo $VMPASSWORD | sudo -S apt-get upgrade -y 
        
        echo "[+]Instalando paqueteria para obtener datos JSON"
        echo $VMPASSWORD | sudo -S apt-get install -y jq

        echo "[+]Descargando Programas para Maquina Virtual Dinamico"
        echo $VMPASSWORD | sudo -S apt-get install -y strace
        echo $VMPASSWORD | sudo -S apt-get install -y ltrace
        echo $VMPASSWORD | sudo -S apt-get install -y gdb
        echo $VMPASSWORD | sudo -S apt-get install -y linux-tools-common linux-tools-generic

elif [[ $HOSTNAME == *estatico ]]; then
        echo "[+]Creando Directorios para Maquina Virtual Estatica"
        
        ./gen 1

        echo $VMPASSWORD | sudo -S apt-get update -y 
        echo $VMPASSWORD | sudo -S apt-get upgrade -y 

        echo "[+]Instalando paqueteria para obtener datos JSON"
        echo $VMPASSWORD | sudo -S apt-get install -y jq

        echo "[+]Descargando Programas para Maquina Virtual Estatica"
        #echo $VMPASSWORD | sudo -S apt-get install -y paquete1 paquete2 paquete3


else
        echo "[-]Maquina virtual incorrecta"
fi






#sudo apt-get install openvpn bridge-utils

#sudo ip tuntap add tap0 mode tap



