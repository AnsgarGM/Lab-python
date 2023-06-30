import os
import sys
import pika
import json
import Const


def create_dirs( directorio_base, estructura ) -> None:
    for nombre, contenido in estructura.items():
        ruta_actual = os.path.join( directorio_base, nombre )
        if not os.path.exists( ruta_actual ):
            os.makedirs( ruta_actual )
            print( "Directorio creado:", ruta_actual )
        
        if isinstance( contenido, dict ):
            create_dirs( ruta_actual, contenido )

def read_parameters() -> dict:
    temp = {
        "name": "Temp",
        "description": "Analisis estatico por el momento",
        "author": "Equipo 15",
        "samples": [],
        "analysis": {
            "static": ["sha1opc", "sha256opc", "md5opc", "fileopc", "exiftool"],
            "dynamic": []
        }
    }

    if len(sys.argv) < 2:
        print("Se esperaba al menos un parámetro.")
        sys.exit(1)

    abs_route = "/home/zoilom/Documentos/AnalisisyDetecciondeMalware/Lab-python/"
    if len( sys.argv ) == 2:
        path = sys.argv[1]
        if os.path.isfile( abs_route + path ) and os.path.isdir( abs_route + path ):
            print( f"La ruta: { abs_route + path } no existe." )
            sys.exit( 1 )
        
        if os.path.isfile( path ):
            if path.endswith( ".json" ):
                # Caso 3: Archivo JSON
                with open( path, "r" ) as file:
                    temp1 = json.load( file )
                    temp["analysis"]["static"] = temp["analysis"]["static"] + temp1["analysis"]["static"]
                    temp["analysis"]["dynamic"] = temp["analysis"]["dynamic"] + temp1["analysis"]["dynamic"]
                    temp["samples"] = temp["samples"] + temp1["samples"]
                    
                return temp
            else:
                # Caso 1: Archivo ejecutable
                temp["samples"].append( path )
                return temp
        elif os.path.isdir( path ):
            # Caso 2: Directorio de ejecutables
            for file in os.listdir( path ):
                if os.path.isfile( path + "/" + file ):
                    temp["samples"].append( file )
            return temp
        
    elif len( sys.argv ) == 3:
        # Caso 4: Archivo JSON y binario
        json_file_path = sys.argv[1]
        binary_file_path = sys.argv[2]
        with open( json_file_path, "r" ) as file:
            temp1 = json.load( file )
            temp["analysis"]["static"] = temp["analysis"]["static"] + temp1["analysis"]["static"]
            temp["analysis"]["dynamic"] = temp["analysis"]["dynamic"] + temp1["analysis"]["dynamic"]
            temp["samples"] = temp["samples"] + temp1["samples"]
        if not binary_file_path in temp["samples"]:
            temp["samples"].append( binary_file_path )
        return temp

def create_experiment( exp_dict ) -> int:
    #pass
    # Carpeta del experimento
    dirs = [ar for ar in os.listdir( Const.EXPERIMENTS ) if os.path.isdir( f"{ Const.EXPERIMENTS }/{ ar }" )]
    #print( dirs )
    max = 0
    if len( dirs ) < 1:
        os.mkdir( f"{ Const.EXPERIMENTS }/1" )
        os.mkdir( f"{ Const.EXPERIMENTS }/1/config_jsons" )
        max = 0
    else:
        for dir in dirs:
            if int( dir ) > max:
                max = int( dir )
        os.mkdir( f"{ Const.EXPERIMENTS }/{ max + 1 }" )
        os.mkdir( f"{ Const.EXPERIMENTS }/{ max + 1 }/config_jsons" )

    
    abs_route = Const.EXPERIMENTS + "/" + str( max + 1 ) + "/"

    # Carpetas de las muestras
    cont = 1
    for _ in exp_dict["samples"]:
        os.mkdir( f"{ abs_route }{ cont }" )
        cont += 1
    
    return max + 1

def translate_experiment( exp_json ) -> None:
    for sample in exp_json["samples"]:
        temp_static = {  
            "malware_name": "",
            "md5opc": "TRUE",
            "sha1opc": "TRUE",
            "sha256opc": "TRUE",
            "strings": "FALSE",
            "fileopc": "TRUE",
            "binheaderopc": "FALSE",
            "symopc": "FALSE",
            "eh_frameopc": "FALSE",
            "callsysopc": "FALSE",
            "libopc": "FALSE",
            "disopc": "FALSE",
            "hexadump": "FALSE",
            "exiftool": "TRUE",
            "loop_exp": 1,
            "static_test":"FALSE",
            "call_sys": "FALSE",
            "lib_sys": "FALSE",
            "lib_sys_time": "FALSE",
            "net_pcap":"FALSE",
            "lsof":"FALSE"
        }
        temp_static["malware_name"] = os.path.basename( sample )
        for command in exp_json["analysis"]["static"]:
            temp_static[command] = "TRUE"
        for command in exp_json["analysis"]["dynamic"]:
            temp_static[command] = "TRUE"
        with open( f"{ Const.EXPERIMENTS }/{ exp_json['id'] }/config_jsons/{ os.path.basename( temp_static['malware_name'] ) }_conf.json", "w" ) as f:
            f.write( json.dumps( temp_static ) )


if __name__ == "__main__":

    # Estructura de directorios
    directorios = {
        "MLWD":{
            "Configuraciones": {
                "Maquinas_virtuales": {
                    "Estatico": {},
                    "Dinamico": {}
                }
            },  
            "Experimentos": {},
        }
    }
    create_dirs( "/home/zoilom/Documentos/AnalisisyDetecciondeMalware/Lab-python", directorios )
    exp_dict = read_parameters()


    #print( "create_experiment" )  
    id = create_experiment( exp_dict )
    exp_dict["id"] = id
    #print( "translate_experiment" )  
    translate_experiment( exp_dict )


    connection = pika.BlockingConnection( pika.ConnectionParameters( 'localhost' ) )
    channel = connection.channel()

    channel.queue_declare( queue = 'cola' )

    channel.basic_publish( exchange = '', routing_key = 'cola', body = json.dumps( exp_dict ) )
    print( exp_dict )

    connection.close()



    print( f"Experimento { id } en cola de ejecución" )
   