import subprocess
import Const
import json


def estado( nombre_maquina ):
    comando = f'VBoxManage showvminfo { nombre_maquina } --machinereadable'
    resultado = subprocess.check_output(comando, shell=True).decode('utf-8')
    estado = ""
    for linea in resultado.splitlines():
        if linea.startswith( "VMState=" ):
            estado = linea.split( '=' )[1].strip( '"' )
            break
    return estado

def iniciar_maquina( nombre_maquina ):
    if estado( nombre_maquina ) == 'poweroff':
        try:
            comando = f'VBoxManage snapshot { nombre_maquina } restore Inicial'
            res = subprocess.run( comando, shell = True, capture_output = True, text = True )
        
            comando = f'VBoxManage startvm { nombre_maquina }'
            res = subprocess.run( comando, shell = True, check = True, capture_output = True, text = True )
        except subprocess.CalledProcessError:
            print( f"Error iniciando maquina { nombre_maquina }" )
            print( res.stderr.strip() )


def apagar_maquina( nombre_maquina ):
    if estado( nombre_maquina ) == 'running':
        try:
            comando = f'VBoxManage controlvm { nombre_maquina } poweroff'
            res = subprocess.run( comando, shell = True, check = True, capture_output = True, text = True )
        except subprocess.CalledProcessError:
            print( f"Error apagando maquina { nombre_maquina }" )
            print( res.stderr.strip() )


def tomar_snapshot( nombre_maquina, nombre_snapshot ):
    comando = f'VBoxManage snapshot { nombre_maquina } take { nombre_snapshot }'
    subprocess.run( comando, shell = True )

def restaurar_snapshot( nombre_maquina, nombre_snapshot ):
    comando = f'VBoxManage snapshot { nombre_maquina } restore { nombre_snapshot }'
    subprocess.run( comando, shell = True )

def enviar_archivo( nombre_maquina, ruta_archivo_host, ruta_destino_vm ):
    # Comando:
    # VBoxManage guestcontrol Estatico copyto "/home/zoilom/Documentos/AnalisisyDetecciondeMalware/Lab-python/prueba_exp.json" /home/analista/Documentos/prueba_exp.json --username analista --password 123456
    comando = f'VBoxManage guestcontrol "{ nombre_maquina }" copyto "{ ruta_archivo_host }" "{ ruta_destino_vm }" --username { json.load( open( Const.STATIC_CONF_JSON ) )["username"] } --password { json.load( open( Const.STATIC_CONF_JSON ) )["password"] }'
    subprocess.run( comando, shell = True )

def recibir_archivo( nombre_maquina, ruta_archivo_vm, ruta_destino_host ):
    comando = f'VBoxManage guestcontrol { nombre_maquina } copyfrom "{ ruta_archivo_vm }" "{ ruta_destino_host }" --username { json.load( open( Const.STATIC_CONF_JSON ) )["username"] } --password { json.load( open( Const.STATIC_CONF_JSON ) )["password"] }'
    subprocess.run( comando, shell = True )

def recibir_carpeta( nombre_maquina, ruta_carpeta_vm, ruta_destino_host ):
    print( "[+] Extrayendo resultados" )
    comando = f'VBoxManage guestcontrol "{ nombre_maquina }" copyfrom --target-directory "{ ruta_destino_host }" --recursive "{ ruta_carpeta_vm }/" --username { json.load( open( Const.STATIC_CONF_JSON ) )["username"] } --password { json.load( open( Const.STATIC_CONF_JSON ) )["password"] }'
    subprocess.run( comando, shell = True )

def vaciar_directorio( nombre_maquina, ruta_dir ):
    comando = f'VBoxManage guestcontrol "{ nombre_maquina }" removedir -R "{ ruta_dir }" --username { json.load( open( Const.STATIC_CONF_JSON ) )["username"] } --password { json.load( open( Const.STATIC_CONF_JSON ) )["password"] }'
    subprocess.run( comando, shell = True )
    comando = f'VBoxManage guestcontrol "{ nombre_maquina }" mkdir "{ ruta_dir }" --username { json.load( open( Const.STATIC_CONF_JSON ) )["username"] } --password { json.load( open( Const.STATIC_CONF_JSON ) )["password"] }'
    subprocess.run( comando, shell = True )

def analisis_estatico():
    comando = f'VBoxManage guestcontrol { json.load( open( Const.STATIC_CONF_JSON ) )["vmname"] } run --exe "/home/analista/Lab/StatScripts/static_service" --username { json.load( open( Const.STATIC_CONF_JSON ) )["username"] } --password { json.load( open( Const.STATIC_CONF_JSON ) )["password"] }'
    subprocess.run( comando, shell = True )

def analisis_dinamico():
    # Ejecutar análisis
    comando = f'VBoxManage guestcontrol { json.load( open( Const.DYNAIC_CONF_JSON ) )["vmname"] } run --exe "/home/analista/Lab/DinScripts/dinacFinal.sh" --username { json.load( open( Const.STATIC_CONF_JSON ) )["username"] } --password { json.load( open( Const.STATIC_CONF_JSON ) )["password"] }'
    subprocess.run( comando, shell = True )



if __name__ == '__main__':
    # Ejemplo de uso
    maquina = "Dinamico"
    snapshot = "Inicial"


    accion = input( "Accion: " )
    if accion == "iniciar":
        iniciar_maquina(maquina)
    # ...esperar a que la máquina virtual se inicie...

    # Realizar tareas en la máquina virtual
    elif accion == "snapshot":
        tomar_snapshot(maquina, snapshot)

    # Realizar más tareas en la máquina virtual
    elif accion == "restaurar":
        restaurar_snapshot(maquina, snapshot)

    elif accion == "apagar":
        apagar_maquina(maquina)

    elif accion == "enviar":
        arch = input( "Archivo: " )
        enviar_archivo(maquina, arch, "/home/analista/Documentos/")
    # ...esperar a que la máquina virtual se apague...

    elif accion == "recibir":
        recibir_archivo(maquina, "/home/analista/Documentos/textoprueba.txt", "/home/zoilom/Documentos/AnalisisyDetecciondeMalware/Lab-python/")
    
    elif accion == "estado":
        print( estado( maquina ) )
    
    elif accion == "movida":
        import time
        apagar_maquina( "Dinamico" )
        time.sleep( 1 )
        iniciar_maquina( "Dinamico" )       

