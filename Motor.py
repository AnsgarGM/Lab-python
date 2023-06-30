from colorama import init, Fore, Style
import threading as th
import VM_func as vm
import json as js
import Const
import pika
import time
import os

        

class Motor:
    def __init__( self ):
        # Agregar configtest.sh a snapshot inicial, agregar hostanme "dinamico" y "estatico"
        self.start_machines( estatico = True, dinamico = True )
        
    def start_static( self ):
        if vm.estado( "Estatico" ) == "poweroff":
            vm.iniciar_maquina( "Estatico" )
        
    def start_dynamic( self ):
        if vm.estado( "Dinamico" ) == "poweroff":
            vm.iniciar_maquina( "Dinamico" )

    def start_machines( self, estatico = False, dinamico = True ):
        if estatico:
            est = th.Thread( target = self.start_static() )
            est.start()
        if dinamico:
            din = th.Thread( target = self.start_dynamic() )
            din.start()

    def send_samples_static( self, samples ):
        for sample in samples:
            vm.enviar_archivo( "Estatico", sample, f"{ Const.BINARY_DIR }/{ os.path.basename( sample ) }" )

            # vm.enviar_archivo( "Dinamico", sample, f"{ Const.BINARY_DIR }/{ os.path.basename( sample ) }" )



    def static_analysis( self, exp_id ):
        """ ------------------------------- Inicio análisis estático ------------------------------- """
        jsons = [ar for ar in os.listdir( f"{ Const.EXPERIMENTS }/{ exp_id }/config_jsons/" ) if os.path.isfile( f"{ Const.EXPERIMENTS }/{ exp_id }/config_jsons/{ ar }" )]
        cont = 1
        for json in jsons:
            
            print( f"{ Fore.BLUE }Analisis estatico: { json }{ Style.RESET_ALL }" )
            # Envia archivo json
            vm.enviar_archivo( "Estatico", f"{ Const.EXPERIMENTS }/{ exp_id }/config_jsons/{ json }", f"{ Const.JSONS_DIR }/config.json" )
            # Iniciar analisis extatico
            vm.analisis_estatico()
            # Extraer resultados
            vm.recibir_carpeta( "Estatico", Const.RESULTS_DIR, f"{ Const.EXPERIMENTS }/{ exp_id }/{ cont }/" )
            # Eliminar archivos de resultados y archivos de configuración 
            vm.vaciar_directorio( "Estatico", f"{ Const.RESULTS_DIR }" )
            vm.vaciar_directorio( "Estatico", f"{ Const.JSONS_DIR }" )
            cont += 1
        # Eliminar binarios
        vm.vaciar_directorio( "Estatico", f"{ Const.BINARY_DIR }" )
        """ ------------------------------- Fin análisis estático ------------------------------- """

    def  dynamic_analysis( self, exp_id, samples ):
        """ ------------------------------- Inicio análisis dinámico ------------------------------- """
        jsons = [ar for ar in os.listdir( f"{ Const.EXPERIMENTS }/{ exp_id }/config_jsons/" ) if os.path.isfile( f"{ Const.EXPERIMENTS }/{ exp_id }/config_jsons/{ ar }" )]
        cont = 1
        for json, sample in zip( jsons, samples ):
            #print( "Json: ", json.split( '_conf.json' )[0] )
            print( f"{ Fore.BLUE }Analisis dinamico: { json.split( '_conf.json' )[0] }{ Style.RESET_ALL }" )
            # Envaia muestra nueva
            vm.enviar_archivo( "Dinamico", sample, f"{ Const.BINARY_DIR }/{ os.path.basename( sample ) }" )
            # Envia archivo json
            vm.enviar_archivo( "Dinamico", f"{ Const.EXPERIMENTS }/{ exp_id }/config_jsons/{ json }", f"{ Const.JSONS_DIR }/config.json" )
            # Iniciar analisis extatico
            vm.analisis_dinamico()
            # Extraer resultados
            vm.recibir_carpeta( "Dinamico", Const.RESULTS_DIR, f"{ Const.EXPERIMENTS }/{ exp_id }/{ cont }/" )
            # Apagar maquina
            vm.apagar_maquina( "Dinamico" )
            # Dormir un ratito pa' que no se atore
            time.sleep( 1 )
            # Restablecer e iniciar maquina
            vm.iniciar_maquina( "Dinamico" )
            cont += 1
        """ ------------------------------- Fin análisis dinámico ------------------------------- """

    def start_experiment( self, experiment ):

        if len( experiment["analysis"]["static"] ) > 0:
            print( Fore.BLUE + "[+] Ejecutando analisis estatico" + Style.RESET_ALL )
            self.send_samples_static( experiment["samples"] )
            static_th = th.Thread( target = self.static_analysis, args = ( experiment['id'], ) )
            static_th.start()

        if len( experiment["analysis"]["dynamic"] ) > 0:
            print( Fore.BLUE + "[+] Ejecutando analisis dinamico" + Style.RESET_ALL )
            dynamic_th = th.Thread( target = self.dynamic_analysis, args = ( experiment['id'], experiment['samples'] ) )
            dynamic_th.start()

        


if __name__ == '__main__':
    connection = pika.BlockingConnection( pika.ConnectionParameters( 'localhost' ) )
    channel = connection.channel()

    channel.queue_declare( queue = 'cola' )


    motor = Motor()
    def pruebita_callback( channel, method, properties, body ):
        motor.start_experiment( js.loads( body ) )
        # print( "Body: ", js.loads( body ) )

    channel.basic_consume( queue = 'cola', on_message_callback = pruebita_callback, auto_ack = True )
    

    init()
    print( Fore.BLUE + "[+] Esperando experimentos..." + Style.RESET_ALL )
    channel.start_consuming()
        # #Iniciar experimento
        # exp = th.Thread( target = motor.start_experiment, args = ( cola.get() ) )
        # exp.start()
