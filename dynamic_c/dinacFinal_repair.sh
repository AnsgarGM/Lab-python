#!/bin/bash

#BASICO dump- CON GCORE , Analisis estaticos, lsof, YARA, API CALL, generar pcap, mandar archivo a virustotal o hybridanalysis
#inotifywait para monitorear eventos en el kernel inotifywait -m (carpeta a checar)

#DECLARANDO VARIABLES DEL PROGRAMA
DINAMICSCRIPTS="/home/analista/Lab/DinScripts"
DOWNLOAD="/home/analista/Lab/download_malware"
JSONPATH="/home/analista/Lab/Json"
LOGS="/home/analista/Lab/Logs"
VMPASSWORD="123456"
NETSCRIPT="netconfig.sh"

##VARIABLES IMPORTANTES
DATE=$(date +%Y%m%d%H%M%S)
JSONFILE="config.json"
LOOP_EXP=""
CALL_SYS=""
LIB_SYS=""
LIB_SYS_TIME=""
GCORE=""

##NOMBRE DE LOGS
CALLSYS_LOG="callsys_$MALWARENAME$DATE.log"
LIBLOG="lib_$MALWARENAME$DATE.log"
LIBTIMELOG="libtime_$MALWARENAME$DATE.log"
GCORELOG="gcore_$MALWARENAME$DATE.log"

##OBTENIENDO OPCIONES DE ANALISIS DINAMICO
ObtenerOpciones(){
MALWARENAME=$(jq -r '.malware_name' $JSONPATH/$JSONFILE)
LOOP_EXP=$(jq -r '.loop_exp' $JSONPATH/$JSONFILE)
CALL_SYS=$(jq -r '.call_sys' $JSONPATH/$JSONFILE)
LIB_SYS=$(jq -r '.lib_sys' $JSONPATH/$JSONFILE)
LIB_SYS_TIME=$(jq -r '.lib_sys_time' $JSONPATH/$JSONFILE)
GCORE=$(jq -r '.gcore' $JSONPATH/$JSONFILE)
}

echo "[+]Comenzando Analisis Dinamico"

echo "[+]Activando Firewall"

ObtenerOpciones

#echo $VMPASSWORD | sudo ./$NETSCRIPT CLOSE 

#Ejecutar Analisis de Red 

cd $DOWNLOAD
echo "123456" | sudo -S chmod 777 $MALWARENAME


echo "123456" | sudo -S iptables -F
   
echo "123456" | sudo -S iptables -P INPUT DROP
echo "123456" | sudo -S iptables -P FORWARD DROP
echo "123456" | sudo -S iptables -P OUTPUT DROP


if [ $CALL_SYS == "TRUE" ]; then

strace -o $LOGS/$CALLSYS_LOG ./$MALWARENAME

fi 

if [ $LIB_SYS == "TRUE" ]; then

ltrace -o $LOGS/$LIBLOG ./$MALWARENAME   

fi

if [ $LIB_SYS_TIME == "TRUE" ]; then

ltrace -c -o  $LOGS/$LIBTIMELOG ./$MALWARENAME  

fi

if [ $GCORE == "TRUE" ]; then
./$Malware &     # Ejecuta el script en segundo plano
pid=$!     
gcore -o $LOGS/$GCORELOG $pid 

fi

echo "123456" | sudo -S iptables -F

echo "123456" | sudo -S iptables -P INPUT ACCEPT
echo "123456" | sudo -S iptables -P FORWARD ACCEPT
echo "123456" | sudo -S iptables -P OUTPUT ACCEPT


