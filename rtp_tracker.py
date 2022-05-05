from rc1_pcap import *
from call_class import *
from math import floor, log10
import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging
import subprocess
import socket
import struct
import re
import statistics
import csv
import threading
import ast
import os


NUM_PAQUETE = 0
NUM_CALL = 0
NUM_PENDING_CALL = 0
NUM_PENDING_ACK_CALL = 0
NUM_CANCEL_CALL = 0
RENEG_NUM_CALL = 0
RENEG_NUM_PENDING_CALL = 0
RENEG_NUM_PENDING_ACK_CALL = 0
PROTOCOLO_IPV4 = "0800"					#Cadena de caracteres que contiene el valor en hexadecimal que indica una cabecera IPv4
PROTOCOLO_IPV6 = "86DD"					#Cadena de caracteres que contiene el valor en hexadecimal que indica una cabecera IPv6
PROTOCOLO_VLAN = "8100"					#Cadena de caracteres que contiene el valor en hexadecimal que indica una cabecera VLAN
MASK_N = 0x0F							#Máscara que nos sirve para extraer el segundo nibble del primer byte de la cabecera IP
MASK_T = 0xF0							#Máscara que nos permite extraer el primer nibble del byte 12 de la cabecera TCP
TIME_TO_EXPIRE = 60.0					#Cantidad de tiempo (en segundos) que determina si una llamada se encuentra inactiva
current_calls = []						#Lista que guarda las llamadas que se estan llevando a cabo
pending_calls = []						#Lista que guarda las llamadas que estan pendientes de ser confirmadas por 200 OK y ACK
pending_ack_calls = []					#Lista que guarda las llamadas que estan pendientes de ser confirmadas por ACK
cancel_calls = []						#Lista que guarda las llamadas que se van a cancelar
current_calls_dict = dict()				#Diccionario para guardar la posición de las llamadas en la lista current_calls
pending_calls_dict = dict()				#Diccionario para guardar la posición de las llamadas en la lista pending_calls
pending_ack_calls_dict = dict()			#Diccionario para guardar la posición de las llamadas en la lista pending_ack_calls
cancel_calls_dict = dict()				#Diccionario para guardar la posición de las llamadas en la lista cancel_calls
reneg_pending_calls = []				#Lista que guarda las llamadas que van a ser renegociadas y estan pendientes de los mensajes 200 OK y ACK
reneg_pending_ack_calls = []			#Lista que guarda las llamadas que van a ser renegociadas y estan pendientes del mensaje ACK
reneg_pending_calls_dict = dict()		#Diccionario que guarda la posicion de las llamadas en la lista reneg_pending_calls
reneg_pending_ack_calls_dict = dict()	#Diccionario que guarda la posicion de las llamadas en la lista reneg_pending_ack_calls
ips_ports_dict = dict()					#Diccionario que asocia las IP's y puertos de origen y destino de una llamada con su call id
rtp_data_dict = dict()					#Diccionario que asocia las IP's y puertos de origen y destino del sentido de una llamada con sus datos RTP
last_packet_received = 0.0				#El instante de tiempo donde se recibio el ultimo paquete
sem = None								#Semaforo utilizado para borrar llamadas
first_rtp_pkt_time = 0
	

def signal_handler(nsignal, frame):
	logging.info('Control C pulsado')
	if handle:
		pcap_breakloop(handle)


def convert_to_ip(hexstr):
	'''
	Función que transforma una cadena de caracteres hexadecimales en una dirección IP.

	Args:
		hexstr (str): Es la cadena de caracteres en hexadecimal.

	Returns:
		str: Cadena de caracteres que contiene la dirección IP equivalente.
	'''
	addr_long = int(hexstr, 16)
	hex(addr_long)
	struct.pack(">L", addr_long)
	return socket.inet_ntoa(struct.pack(">L", addr_long))


def process_regex(regex):
	'''
	Función que procesa una expresión regular para que pueda ser usada eliminando algunos caracteres.

	Args:
		regex (str): Expresión regular a procesar.

	Returns:
		str: Expresión regular procesada (se eliminan retornos de carro y saltos de línea).
	'''
	regex = regex.group()
	regex = regex.replace('\r','')
	regex = regex.replace('\n','')
	return regex


def combine(seconds, microsecs):
	'''
	Función que transforma un tiempo de epoch time a segundos.

	Args:
		seconds (int): Parte en segundos del epoch time.
		microsecs (int): Parte en microsegundos del epoch time.

	Returns:
		float: Tiempo transformado a segundos.
	'''
	time = seconds + microsecs/1000000

	return time


def represent_data_cancel(obj):
	'''
	Funcion que representa la informacion de una llamada cuando es cancelada

	Args:
		obj: Objeto que contiene los datos de la llamada cancelada
	'''
	with open (obj.call_id + '_cancel_info.txt', mode='w') as rtp_data_file:

		file_writer = csv.writer(rtp_data_file, delimiter='\t')
		file_writer.writerow(["|1CallID|", "|4DestAddr|", "|5DestPort|", "|6ErrorMsg|", "|7ErrorCode|"])
		file_writer.writerow([obj.call_id, obj.rtp_ip_dest, obj.rtp_port_dest, obj.error_message, obj.error_code])


def represent_data(obj_list, path):
	'''
	Función que escribe en un fichero todos los cálculos RTP de una llamada.

	Args:
		obj_list (list[Call_Data]): Lista que contiene dos objetos con los datos RTP de los dos sentidos de la llamada.
	''' 
	call_id_aux = obj_list[0].call_id

	dir_path = path + "/" + call_id_aux + "/rtp_data"

	try:
		if os.path.exists(dir_path) == False:
			os.makedirs(dir_path)
	except OSError:
		print("No pudo crearse el directorio /" + call_id_aux + "/rtp_data")

	with open(os.path.join(dir_path, call_id_aux + '_rtp_data.txt'), mode='w') as rtp_data_file:

		file_writer = csv.writer(rtp_data_file, delimiter='\t')
		file_writer.writerow(["|1CallID|", "|2SrcAddr|", "|3SrcPort|", "|4DestAddr|", "|5DestPort|", "|6StartT|", "|7EndT|", "|8SSRC|", "|9Payload|", 
								  "|10Packets|", "|11Lost(%)|", "|12MaxDelta(ms)|", "|13MaxJitter(ms)|", "|14MeanJitter(ms)|"])

		for obj in obj_list:
			if obj.num_total_packets != 0:
				pa_lo = obj.num_lost_packets*100 / obj.num_total_packets
				max_delta = max(obj.delay_list)
				max_jitter = max(obj.jitter_list)
				total_jitter = 0
				for jitter in obj.jitter_list:
					total_jitter += jitter

				mean_jitter = total_jitter/len(obj.jitter_list)

				if obj.payload == 8:
					payload_type = "g711A"
				elif obj.payload == 9:
					payload_type = "g722"
				else:
					payload_type = "g711U"

				file_writer.writerow([obj.call_id, obj.rtp_ip_src, obj.rtp_port_src, obj.rtp_ip_dest, obj.rtp_port_dest, obj.time_begin, obj.time_end,
									  "0x"+str(obj.ssrc), payload_type, obj.num_total_packets-obj.num_lost_packets, round(pa_lo, 1), round(max_delta, 2), 
									  round(max_jitter, 2), round(mean_jitter, 2)])
			else:
				file_writer.writerow([obj.call_id, obj.rtp_ip_src, obj.rtp_port_src, obj.rtp_ip_dest, obj.rtp_port_dest])



def write_audio_file(obj_list, path):
	'''
	Función que genera dos archivos con el audio de los dos sentidos de la llamada.

	Args:
		obj_list (list[Call_Data]): Lista que contiene dos objetos con los datos RTP de los dos sentidos de la llamada.
	'''
	i = 1
	for obj in obj_list:
		dir_path = path + "/" + obj.call_id + "/audio"

		try:
			if os.path.exists(dir_path) == False:
				os.makedirs(dir_path)
		except OSError:
			print("No pudo crearse el directorio /" + obj.call_id + "/audio")

		file = open(os.path.join(dir_path, obj.call_id + "-file" + str(i) + ".raw"), "wb")
		for line in obj.rtp_audio_list:
			file.write(line)
			
		i += 1
		file.close()


def garbage_collector():
	'''
	Función que se activa cada 60 segundos. Comprueba si una llamada se encuentra inactiva, en ese caso, la elimina.
	'''
	#print("EN EL GARBAGE COLECTOR")
	sem.acquire()
	for key in rtp_data_dict.keys():
		obj = rtp_data_dict[key]
		if (last_packet_received - obj.arrival_prev_packet) >= TIME_TO_EXPIRE:
			delete_call(obj.call_id)
			
	sem.release()


def cancel_callf(call_id, num_pending_call, num_cancel_call):
	'''
	Funcion que elimina una llamada de los registros correspondientes cuando esta es cancelada.

	Args:
		call_id: Id de la llamada a cancelar.
		num_pending_call: El numero de llamadas pendientes de aprobar con un 200 OK.
		num_cancel_call: El numero de llamadas pendientes de cancelar.
	Return:
		cancelled_call: El objeto que contiene los datos de la llamada que se ha cancelado.
		num_pending_call: El numero de llamadas pendientes de aprobar con un 200 OK actualizado.
		num_cancel_call: El numero de llamadas pendientes de cancelar actualizado.
	'''
	pos = pending_calls_dict[call_id]

	val_list = list(pending_calls_dict.values())
	val_index = val_list.index(pos)

	del pending_calls_dict[call_id]

	cont = 0
	for key in pending_calls_dict.keys():
		if cont >= val_index:
			pending_calls_dict[key] -= 1
			cont += 1
		else:
			cont += 1

	pending_calls.pop(pos)
	num_pending_call -= 1

	pos = cancel_calls_dict[call_id]

	val_list = list(cancel_calls_dict.values())
	val_index = val_list.index(pos)

	del cancel_calls_dict[call_id]

	cont = 0
	for key in cancel_calls_dict.keys():
		if cont >= val_index:
			cancel_calls_dict[key] -= 1
			cont += 1
		else:
			cont += 1

	cancelled_call = cancel_calls.pop(pos)
	num_cancel_call -= 1

	return cancelled_call, num_pending_call, num_cancel_call


def delete_call(call_id, num_call):
	'''
	Función que elimina una llamada de todos los registros.

	Args:
		call_id: Id de la llamada a eliminar.
		num_call: El numero de llamadas en curso.
	Return:
		obj_list: Lista con los contenedores de datos de las llamadas a eliminar.
		num_call: El numero de llamadas en curso actualizado.
	'''
	obj_list = []

	#Conseguimos la posicion de la llamada que queremos eliminar en la lista de llamadas actuales
	pos = current_calls_dict[call_id]
	#Obtenemos el indice en la lista de values del valor a eliminar
	val_list = list(current_calls_dict.values())
	val_index = val_list.index(pos)
	#Eliminamos la llamada del diccionario
	del current_calls_dict[call_id]

	#Mediante este bucle, actualizamos el indice de las llamadas actuales siguientes a la que eliminamos
	cont = 0
	for key in current_calls_dict.keys():
		if cont >= val_index:
			current_calls_dict[key] -= 1
			cont += 1
		else:
			cont += 1

	#Eliminamos la llamada de la lista de llamadas actuales
	current_calls.pop(pos)
	num_call -= 1

	#Eliminamos los registros de la llamada en los diccionarios ips_ports_dict y rtp_data_dict. Antes de eliminar,
	#recuperamos el objeto que guarda los datos de los sentidos de la llamada
	for key in list(ips_ports_dict.keys()):
		if ips_ports_dict[key] == call_id:
			obj_list.append(rtp_data_dict[key])
			del ips_ports_dict[key]
			del rtp_data_dict[key]

	return obj_list, num_call


def procesa_paquete(us, header, data):
	'''
	Función callback que se ejecuta cada vez que se recibe un paquete. Contiene toda la funcionalidad de la monitorización de las llamadas.

	Args:
		us: Datos auxiliares del usuario pasados a pcap_loop.
		header: Objeto de tipo pcap_pkthdr que contiene la cabecera pcap del paquete leído o capturado. Este objeto tiene tres campos:
			pkt_header.ts: objeto timestamp que contiene el tiempo de captura del paquete. Tiene a su vez dos campos:
				ts.tv_sec: Timestamp del paquete en segundos.
				ts.tv_usec: Timestamp del paquete en microsegundos.
			pkt_header.len: Longitud real del paquete.
			pkt_header.caplen: Longitud capturada del paquete.
		data: Bytearray que contiene los datos del paquete.
	'''
	global NUM_PAQUETE, NUM_PENDING_CALL, NUM_PENDING_ACK_CALL, NUM_CALL, RENEG_NUM_CALL, RENEG_NUM_PENDING_CALL, RENEG_NUM_PENDING_ACK_CALL, NUM_CANCEL_CALL, first_rtp_pkt_time
	is_response = False
	is_silence = False
	is_lost = False

	logging.info("Nuevo paquete de {} bytes capturado.".format(header.len))
	NUM_PAQUETE += 1

	#Obtenemos y analizamos el tipo de protocolo de la trama siguiente a la de Ethernet
	protocol_type = data[12:14].hex().upper()

	#Este bloque comprueba si la siguiente trama es IP
	if protocol_type == PROTOCOLO_IPV4 or protocol_type == PROTOCOLO_IPV6:
		index = 14
	#Este bloque comprueba si la trama Ethernet contiene una etiqueta VLAN, en ese caso, el bucle nos permite
	#avanzar por la trama hasta encontrar los bytes que nos indican el comienzo de la cabecera IP
	elif protocol_type == PROTOCOLO_VLAN:
		index = 18
		while protocol_type != "0021":
			protocol_type = data[index:(index+2)].hex()
			index += 2

	if protocol_type == "0021":
		protocol_type = PROTOCOLO_IPV4

	#Separamos la trama Ethernet de los datos del paquete
	ethernet_data = data[:index]

	'''
	Obtenemos los datos correspondientes al Nivel 2 (Ethernet):
	- MAC destino
	- MAC origen
	'''
	mac_dest = ethernet_data[:6].hex(':')
	mac_src = ethernet_data[6:12].hex(':')
	#print("Direccion MAC destino: {}".format(mac_dest))
	#print("Direccion MAC origen: {}".format(mac_src))
	#print("Tipo de protocolo: {}".format(protocol_type))

	'''
	Obtenemos los datos correspondientes al Nivel 3 (IP):
	- Dirección IP origen
	- Dirección IP destino
	- Protocolo de transporte
	- Tamaño de la cabecera IP
	'''
	transport_protocol = 0

	#Si el protocolo es IPv4, el programa entra aquí
	if protocol_type == PROTOCOLO_IPV4:
		#Obtenemos el primer byte de la cabecera IPv4
		ip_header_lenght = data[index]
		#Extraemos el segundo nibble del primer byte de la cabecera IPv4 y lo convertimos a bytes para obtener la longitud de
		#la cabecera IP
		ip_header_lenght = (ip_header_lenght&MASK_N)*4

		#Separamos la trama IPv4 de los datos del paquete
		ip_data = data[index:(index+ip_header_lenght)]

		#Obtenemos las IP's de origen y destino, así como el protocolo de transporte
		ip_src = convert_to_ip(ip_data[12:16].hex())
		ip_dest = convert_to_ip(ip_data[16:].hex())
		transport_protocol = ip_data[9]

	#Si el protocolo es IPv6, el programa entra aquí
	elif protocol_type == PROTOCOLO_IPV6:

		#Obtenemos la longitud de la cabecera IPv6 y la convertimos a int
		#Si el tamaño es menor que 40 bytes le pondremos como valor 40
		if int(data[index+4:index+6].hex(), 16) >= 40:
			ip_header_lenght = int(data[index+4:index+6].hex(), 16)
		else:
			ip_header_lenght = 40

		#Separamos la trama IPv6 de los datos del paquete
		ip_data = data[index:(index+ip_header_lenght)]
		#print(ip_data)

		next_header = ip_data[6]

		if next_header == 6 or next_header == 17:

			ipv6_data = data[index:(index+40)]

			ip_src = ipv6_data[8:24].hex()
			ip_dest = ipv6_data[24:].hex()
			transport_protocol = ipv6_data[6]
			print("Direccion IP origen: {}".format(ip_src))
			print("Direccion IP destino: {}".format(ip_dest))
			print("Protocolo: {}".format(transport_protocol))
			#print("Tamaño de la cabecera: {} bytes".format(ip_header_lenght))

		elif next_header == 43 or next_header == 44:

			current_header = next_header
			exp_header_index = 0

			#Este bucle se encarga de pasar por todas las capas de expansion que pueda haber
			while current_header != 41:
				#Obtenemos el tipo de la siguiente cabecera
				next_header = ip_data[exp_header_index+40]
				print("NEXT HEADER ", next_header)

				#Cabecera de Enrutamiento
				if current_header == 43:
					#Obtenemos la longitud de la cabecera y calculamos su longitud en octetos mas los 8 primeros octetos
					exp_header_length = ip_data[exp_header_index+41]
					exp_header_length_real = (exp_header_length*8)+8
					print("HEADER LENGTH ", exp_header_length_real)

					#Actualizamos el valor del indice sumandole la longitud de la cabecera actual
					exp_header_index += exp_header_length_real

				#Cabecera de Fragmento
				elif current_header == 44:
					#Las cabeceras de fragmento tienen un valor fijo de 8 bytes
					exp_header_index += 8

				else:
					print("OTRO TIPO DE CABECERA DE EXPANSION")

				current_header = next_header

			ipv6_data = data[(index+exp_header_index+40):(index+exp_header_index+80)]
			print(ipv6_data)

			ip_src = ipv6_data[8:24].hex()
			ip_dest = ipv6_data[24:].hex()
			transport_protocol = ipv6_data[6]

	#Si el protocolo de transporte es TCP (6) o UDP (17) el programa entra aquí.
	if transport_protocol == 6 or transport_protocol == 17:
		'''
		Obtenemos los datos correspondientes al Nivel 4 (Transporte):
		- Puerto origen
		- Puerto destino
		'''
		#Separamos la trama de transporte de los datos del paquete y obtenemos los puertos de origen y destino
		transport_data = data[(index+ip_header_lenght):(index+ip_header_lenght+4)]
		src_port = int(transport_data[:2].hex(), 16)
		dest_port = int(transport_data[2:4].hex(), 16)

		#Comprobamos si el protocolo de transporte es TCP
		if transport_protocol == 6:
			transport_header_lenght = data[(index+ip_header_lenght+12)]
			#Extraemos el primer nibble del byte 12 de la cabecera TCP y lo convertimos a bytes para conocer
			#la longitud de la trama TCP
			transport_header_lenght = ((transport_header_lenght&MASK_T)>>4)*4
		#Si no es TCP, el protocolo de transporte es UDP
		else:
			#La trama UDP es constante de 8 bytes
			transport_header_lenght = 8

		#Comprobamos si el paquete se trata de un paquete SIP
		if ((src_port == 5060 or src_port == 5061) or (dest_port == 5060 or dest_port == 5061)):

			#Obtenemos la trama SIP del paquete
			sip_data = data[(index+ip_header_lenght+transport_header_lenght):]

			#Convertimos la trama SIP a un string
			sip_string = bytes.fromhex(sip_data.hex()).decode("utf-8")
			#print(sip_string)

			#Abrimos el fichero de respuestas SIP y lo importamos a un diccionario
			file = open("sip_responses", "r")
			sip_responses = file.read()
			sip_responses_dict = ast.literal_eval(sip_responses)
			file.close()

			#Comprobamos si el paquete corresponde a una respuesta SIP o no. En cuanto se detecte que es una
			#respuesta SIP, salimos del bucle.
			for response in sip_responses_dict.keys():
				#Buscamos la respuesta en la trama SIP
				match = re.search(response, sip_string)
				#Respuesta encontrada
				if match:
					#Obtenemos el codigo de la respuesta
					code = sip_responses_dict[response]
					#Este flag lo activamos si el paquete se trata de una respuesta
					is_response = True
					#Si la respuesta es un OK entramos aquí
					if code == 200:
						#Obtenemos el id de la llamada
						call_id_response = re.search("(?s)(?<=Call-ID: ).*?(?=CSeq)", sip_string)
						call_id_response = process_regex(call_id_response)

						#Comprobamos si el OK corresponde con una llamada en proceso de ser aceptada
						try:
							pos = pending_calls_dict[call_id_response]

						#En caso negativo, puede ser el OK de un INVITE de una llamada ya en curso (una renegociacion) o de un REGISTER
						except KeyError:

							#Comprobamos si el OK corresponde con una llamada de renegociacion en proceso de ser aceptada
							try:
								pos = reneg_pending_calls_dict[call_id_response]
							#OK de REGISTER
							except KeyError:
								return
							#OK de INVITE de renegociacion
							else:
								#Obtenemos la informacion necesaria para llevar a cabo la renegociacion
								rtp_ip_src = re.search("(?s)(?<=IP4 ).*?(?=s\=)", sip_string)
								rtp_ip_src = process_regex(rtp_ip_src)
								rtp_port_src = re.search("(?s)(?<=audio ).*?(?= RTP/AVP)", sip_string)
								rtp_port_src = process_regex(rtp_port_src)
								#Obtenemos el objeto de renegociacion y lo eliminamos de los registros en los que ya no es necesario
								reneg = reneg_pending_calls.pop(pos)
								RENEG_NUM_PENDING_CALL -= 1
								del reneg_pending_calls_dict[call_id_response]
								#Asignamos al objeto los nuevos datos de la llamada y lo guardamos en los registros correspondientes
								reneg.rtp_ip_src = rtp_ip_src
								reneg.rtp_port_src = rtp_port_src
								reneg_pending_ack_calls_dict[call_id_response] = RENEG_NUM_PENDING_ACK_CALL
								RENEG_NUM_PENDING_ACK_CALL += 1
								reneg_pending_ack_calls.append(reneg)

						#Llegados a este punto, se trata de un OK de INVITE o de CANCEL
						else:
							#Se trata de un OK de CANCEL
							if call_id_response in cancel_calls_dict:
								return

							#Se trata de un OK de INVITE
							#Obtenemos la informacion que nos proporciona el paquete
							rtp_ip_src = re.search("(?s)(?<=IP4 ).*?(?=s\=)", sip_string)
							rtp_ip_src = process_regex(rtp_ip_src)
							rtp_port_src = re.search("(?s)(?<=audio ).*?(?= RTP/AVP)", sip_string)
							rtp_port_src = process_regex(rtp_port_src)

							try:
								call = pending_calls.pop(pos)
							except IndexError:
								#print("ID", call_id_response)
								#print(pending_calls)
								call = pending_calls.pop(pos-1)
								#print("ID LLAMADA", call.call_id)

							NUM_PENDING_CALL -= 1
							del pending_calls_dict[call_id_response]
							call.rtp_ip_src = rtp_ip_src
							call.rtp_port_src = rtp_port_src
							ip_port_tuple = (call.rtp_ip_dest, call.rtp_port_dest, call.rtp_ip_src, call.rtp_port_src)
							ip_port_tuple2 = (call.rtp_ip_src, call.rtp_port_src, call.rtp_ip_dest, call.rtp_port_dest)
							ips_ports_dict[ip_port_tuple] = call_id_response
							ips_ports_dict[ip_port_tuple2] = call_id_response

							#Creamos el objeto que guarda los datos RTP del sentido de una llamada e inicializamos sus valores
							rtp_call_data1 = Call_Data()
							rtp_call_data1.call_id = call_id_response
							rtp_call_data1.rtp_ip_src = call.rtp_ip_src
							rtp_call_data1.rtp_port_src = call.rtp_port_src
							rtp_call_data1.rtp_ip_dest = call.rtp_ip_dest
							rtp_call_data1.rtp_port_dest = call.rtp_port_dest
							rtp_call_data1.seq_num_prev_packet = -1
							rtp_call_data1.tmstmp_prev_packet = -1
							rtp_call_data1.time_difference = -1
							rtp_call_data1.num_total_packets = 0
							rtp_call_data1.num_lost_packets = 0
							rtp_call_data1.arrival_prev_packet = -1
							rtp_call_data1.delay_list = []
							rtp_call_data1.jitter_prev_packet = -1
							rtp_call_data1.jitter_list = []
							rtp_call_data1.ssrc = ""
							rtp_call_data1.rtp_audio_list = []
							rtp_call_data1.time_begin = -1
							rtp_call_data1.time_end = -1

							#Creamos el objeto que guarda los datos del otro sentido de la llamada
							rtp_call_data2 = Call_Data()
							rtp_call_data2.call_id = call_id_response
							rtp_call_data2.rtp_ip_src = call.rtp_ip_dest
							rtp_call_data2.rtp_port_src = call.rtp_port_dest
							rtp_call_data2.rtp_ip_dest = call.rtp_ip_src
							rtp_call_data2.rtp_port_dest = call.rtp_port_src
							rtp_call_data2.seq_num_prev_packet = -1
							rtp_call_data2.tmstmp_prev_packet = -1
							rtp_call_data2.time_difference = -1
							rtp_call_data2.num_total_packets = 0
							rtp_call_data2.num_lost_packets = 0
							rtp_call_data2.arrival_prev_packet = -1
							rtp_call_data2.delay_list = []
							rtp_call_data2.jitter_prev_packet = -1
							rtp_call_data2.jitter_list = []
							rtp_call_data2.ssrc = ""
							rtp_call_data2.rtp_audio_list = []
							rtp_call_data2.time_begin = -1
							rtp_call_data2.time_end = -1

							#Introducimos los valores en el diccionario: key -> tupla, value -> clase con los datos RTP
							sem.acquire()
							rtp_data_dict[ip_port_tuple2] = rtp_call_data1
							rtp_data_dict[ip_port_tuple] = rtp_call_data2
							sem.release()

							pending_ack_calls_dict[call_id_response] = NUM_PENDING_ACK_CALL
							NUM_PENDING_ACK_CALL += 1
							pending_ack_calls.append(call)

					elif code >= 300:
						call_id_response = re.search("(?s)(?<=Call-ID: ).*?(?=CSeq)", sip_string)
						call_id_response = process_regex(call_id_response)

						pos = cancel_calls_dict[call_id_response]

						cancel_calls[pos].error_message = response
						cancel_calls[pos].error_code = code

					break

			if is_response is False:
				sip_header = sip_string
				match_allow = re.search("Allow", sip_string)
				if match_allow:
					index = sip_string.index("Allow")
					string_to_delete = sip_string[index:]
					sip_header = sip_string.replace(string_to_delete, "")

				match_invite = re.search("INVITE", sip_header)
				match_bye = re.search("BYE", sip_header)
				match_ack = re.search("ACK", sip_header)
				match_cancel = re.search("CANCEL", sip_header)

				#Mensaje ACK
				if match_ack:
					#print("Mnesaje ACK")
					call_id_ack = re.search("(?s)(?<=Call-ID: ).*?(?=CSeq)", sip_header)
					call_id_ack = process_regex(call_id_ack)

					#Mensaje ACK de CANCEL
					if call_id_ack in cancel_calls_dict:
						cancelled_call, NUM_PENDING_CALL, NUM_CANCEL_CALL = cancel_call(call_id_ack, NUM_PENDING_CALL, NUM_CANCEL_CALL)

						represent_data_cancel(cancelled_call)

					#Mensaje ACK de INVITE
					else:
						try:
							pos = pending_ack_calls_dict[call_id_ack]
						except KeyError:

							try:
								pos = reneg_pending_ack_calls_dict[call_id_ack]
							except KeyError:
								print("AQUI NO SE PUEDE LLEGAR, ALGO FUE MAL")
								return
							else:
								reneg = reneg_pending_ack_calls.pop(pos)
								RENEG_NUM_PENDING_ACK_CALL -= 1
								del reneg_pending_ack_calls_dict[call_id_ack]
								call = current_calls.pop(pos)

								#Actualizamos el diccionario rtp_data_dict con la nueva información
								rtp_data_dict[tuple((reneg.rtp_ip_dest, reneg.rtp_port_dest, reneg.rtp_ip_src, reneg.rtp_port_src))] = rtp_data_dict.pop(tuple((call.rtp_ip_dest, call.rtp_port_dest, call.rtp_ip_src, call.rtp_port_src)))
								rtp_data_dict[tuple((reneg.rtp_ip_src, reneg.rtp_port_src, reneg.rtp_ip_dest, reneg.rtp_port_dest))] = rtp_data_dict.pop(tuple((call.rtp_ip_src, call.rtp_port_src, call.rtp_ip_dest, call.rtp_port_dest)))

								#Actualizamos el objeto que contiene los datos RTP
								for key in list(rtp_data_dict.keys()):
									if key == tuple((reneg.rtp_ip_dest, reneg.rtp_port_dest, reneg.rtp_ip_src, reneg.rtp_port_src)):
										rtp_data_dict[key].rtp_ip_src = reneg.rtp_ip_dest
										rtp_data_dict[key].rtp_port_src = reneg.rtp_port_dest
										rtp_data_dict[key].rtp_ip_dest = reneg.rtp_ip_src
										rtp_data_dict[key].rtp_port_dest = reneg.rtp_port_src
									elif key == tuple((reneg.rtp_ip_src, reneg.rtp_port_src, reneg.rtp_ip_dest, reneg.rtp_port_dest)):
										rtp_data_dict[key].rtp_ip_src = reneg.rtp_ip_src
										rtp_data_dict[key].rtp_port_src = reneg.rtp_port_src
										rtp_data_dict[key].rtp_ip_dest = reneg.rtp_ip_dest
										rtp_data_dict[key].rtp_port_dest = reneg.rtp_port_dest


								#Actualizamos el diccionario ips_ports_dict con la nueva información
								ips_ports_dict[tuple((reneg.rtp_ip_dest, reneg.rtp_port_dest, reneg.rtp_ip_src, reneg.rtp_port_src))] = ips_ports_dict.pop(tuple((call.rtp_ip_dest, call.rtp_port_dest, call.rtp_ip_src, call.rtp_port_src)))
								ips_ports_dict[tuple((reneg.rtp_ip_src, reneg.rtp_port_src, reneg.rtp_ip_dest, reneg.rtp_port_dest))] = ips_ports_dict.pop(tuple((call.rtp_ip_src, call.rtp_port_src, call.rtp_ip_dest, call.rtp_port_dest)))

								#Actualizamos el objeto de la llamada con la nueva información y lo guardamos en la lista de llamadas actuales
								call.rtp_ip_dest = reneg.rtp_ip_dest
								call.rtp_port_dest = reneg.rtp_port_dest
								call.rtp_ip_src = reneg.rtp_ip_src
								call.rtp_port_src = reneg.rtp_port_src
								current_calls.append(call)

						else:
							call = pending_ack_calls.pop(pos)
							NUM_PENDING_ACK_CALL -= 1
							del pending_ack_calls_dict[call_id_ack]
							current_calls_dict[call_id_ack] = NUM_CALL
							NUM_CALL += 1
							current_calls.append(call)
					
				#Mensaje INVITE	
				elif match_invite:
					#print("MENSAJE INVITE")
					from_to_list = re.findall("<([^<^>]*)>", sip_header)
					if len(from_to_list) > 2:
						del from_to_list[2:]

					froom = from_to_list.pop(0)
					to = from_to_list.pop(0)

					call_id = re.search("(?s)(?<=Call-ID: ).*?(?=CSeq)", sip_header)
					call_id = process_regex(call_id)
					#print(call_id)

					index = sip_string.index("c=")
					aux_string = sip_string[index:]

					try:
						pos = current_calls_dict[call_id]
					except KeyError:
						rtp_ip_dest = re.search("(?s)(?<=IP4 ).*?(?=t\=)", aux_string)
						rtp_ip_dest = process_regex(rtp_ip_dest)
						rtp_port_dest = re.search("(?s)(?<=audio ).*?(?= RTP/AVP)", aux_string)
						rtp_port_dest = process_regex(rtp_port_dest)
						call = Call()
						call.call_id = call_id
						call.froom = froom
						call.to = to
						call.rtp_ip_dest = rtp_ip_dest
						call.rtp_port_dest = rtp_port_dest
						pending_calls_dict[call_id] = NUM_PENDING_CALL
						NUM_PENDING_CALL += 1
						pending_calls.append(call)
					else:
						rtp_ip_dest = re.search("(?s)(?<=IP4 ).*?(?=t\=)", aux_string)
						rtp_ip_dest = process_regex(rtp_ip_dest)
						rtp_port_dest = re.search("(?s)(?<=audio ).*?(?= RTP/AVP)", aux_string)
						rtp_port_dest = process_regex(rtp_port_dest)
						reneg = Renegotiation()
						reneg.rtp_ip_dest = rtp_ip_dest
						reneg.rtp_port_dest = rtp_port_dest
						reneg_pending_calls_dict[call_id] = RENEG_NUM_PENDING_CALL
						RENEG_NUM_PENDING_CALL += 1
						reneg_pending_calls.append(reneg)

				#Mensaje BYE
				elif match_bye:
					#Obtenemos el id de la llamada del cuerpo del mensaje
					call_id = re.search("(?s)(?<=Call-ID: ).*?(?=CSeq)", sip_header)
					call_id = process_regex(call_id)

					tuple1 = tuple()
					tuple2 = tuple()

					for key in list(ips_ports_dict.keys()):
						if ips_ports_dict[key] == call_id:
							if tuple1:
								tuple2 = key
							else:
								tuple1 = key

					obj1 = rtp_data_dict[tuple1]
					obj2 = rtp_data_dict[tuple2]

					#Establecemos el tiempo en el que comenzo la llamada (el mas pequeño)
					min_aux = min(obj1.time_begin, obj2.time_begin)
					obj1.time_begin = min_aux - first_rtp_pkt_time
					obj2.time_begin = min_aux - first_rtp_pkt_time

					#Establecemos el tiempo en el que finalizo la llamada
					obj1.time_end = combine(header.ts.tv_sec, header.ts.tv_usec) - first_rtp_pkt_time
					obj2.time_end = combine(header.ts.tv_sec, header.ts.tv_usec) - first_rtp_pkt_time

					sem.acquire()
					obj_list, NUM_CALL = delete_call(call_id, NUM_CALL)
					sem.release()

					path = os.getcwd()

					#Generamos los archivos de audio de la llamada
					write_audio_file(obj_list, path)

					#Representamos los calculos RTP de la llamada
					represent_data(obj_list, path)

				#Mensaje CANCEL
				elif match_cancel:
					#Obtenemos el id de la llamada a cancelar
					call_id = re.search("(?s)(?<=Call-ID: ).*?(?=CSeq)", sip_header)
					call_id = process_regex(call_id)

					pos = pending_calls_dict[call_id]

					cancel_call = Cancel_Data()
					cancel_call.call_id = call_id
					cancel_call.rtp_ip_dest = pending_calls[pos].rtp_ip_dest
					cancel_call.rtp_port_dest = pending_calls[pos].rtp_port_dest

					cancel_calls_dict[call_id] = NUM_CANCEL_CALL
					NUM_CANCEL_CALL += 1
					cancel_calls.append(cancel_call)

				else:
					print("ES OTRO MENSAJE", NUM_PAQUETE)


		elif tuple((str(ip_src), str(src_port), str(ip_dest), str(dest_port))) in ips_ports_dict:

			#Obtenemos la trama RTP del paquete
			rtp_data = data[(index+ip_header_lenght+transport_header_lenght):]

			#Convertimos la trama RTP a un string hexadecimal
			rtp_string = bytes(rtp_data.hex(),'iso-8859-1').decode('utf-8')

			payload_type = int(rtp_string[2:4], 16)
			mark = ((payload_type&MASK_T)>>4)
			sequence_number = int(rtp_string[4:8], 16)
			timestamp = int(rtp_string[8:16], 16)
			src_id = rtp_string[16:24]

			if len(rtp_data) <= 13:
				return
			else:
				if rtp_data[13] == 0:
					payload = rtp_data[12].to_bytes(1, "little")
				else:
					payload = rtp_data[12:]


			rtp_data_obj = rtp_data_dict[tuple((str(ip_src), str(src_port), str(ip_dest), str(dest_port)))]

			if rtp_data_obj.ssrc != src_id:
				rtp_data_obj.arrival_prev_packet = -1
				rtp_data_obj.jitter_prev_packet = -1
				rtp_data_obj.delay_list.clear()
				rtp_data_obj.jitter_list.clear()
				
			rtp_data_obj.ssrc = src_id
			rtp_data_obj.payload = payload_type

			#Guardamos el tiempo de llegada del primer paquete RTP del archivo de red
			if first_rtp_pkt_time == 0:
				first_rtp_pkt_time = combine(header.ts.tv_sec, header.ts.tv_usec)

			#print(first_rtp_pkt_time)

			#Guardamos el tiempo en el que llega el primer paquete RTP de cada sentido (comienzo de la llamada)
			if rtp_data_obj.time_begin == -1:
				rtp_data_obj.time_begin = combine(header.ts.tv_sec, header.ts.tv_usec)

			#Este bloque se encarga de detectar si se produce algun silencio en la llamada
			if rtp_data_obj.tmstmp_prev_packet != -1:
				difference = timestamp - rtp_data_obj.tmstmp_prev_packet
				rtp_data_obj.time_difference = difference if rtp_data_obj.time_difference == -1 else rtp_data_obj.time_difference
				if difference != rtp_data_obj.time_difference:
					silence_size = timestamp - rtp_data_obj.tmstmp_prev_packet - rtp_data_obj.frames_prev_packet
					is_silence = True

				rtp_data_obj.tmstmp_prev_packet = timestamp
				rtp_data_obj.frames_prev_packet = len(payload)
			else:
				rtp_data_obj.tmstmp_prev_packet = timestamp
				rtp_data_obj.frames_prev_packet = len(payload)
				difference = 0

			#Aumentamos en 1 el numero de paquetes emitidos
			rtp_data_obj.num_total_packets += 1

			#Este bloque se encarga de llevar una cuenta de los paquetes que se han perdido, si ha habido alguno
			if rtp_data_obj.seq_num_prev_packet != -1:
				seq_difference = sequence_number - rtp_data_obj.seq_num_prev_packet
				if seq_difference != 1 and seq_difference > 0:
					rtp_data_obj.num_lost_packets += (seq_difference - 1)
					rtp_data_obj.num_total_packets += (seq_difference - 1)
					silence_size = silence_size / (seq_difference - 1)		#<--- PROBAR SI FUNCIONA
					is_lost = True

				rtp_data_obj.seq_num_prev_packet = sequence_number
			else:
				rtp_data_obj.seq_num_prev_packet = sequence_number

			#Este bloque se encarga de medir el tiempo de llegada entre paquetes para calcular el Max Delta
			if rtp_data_obj.arrival_prev_packet != -1:
				delay = combine(header.ts.tv_sec, header.ts.tv_usec) - rtp_data_obj.arrival_prev_packet
				rtp_data_obj.arrival_prev_packet = combine(header.ts.tv_sec, header.ts.tv_usec)
				if mark == 0:
					rtp_data_obj.delay_list.append(round(delay*1000, 2))
			else:
				rtp_data_obj.arrival_prev_packet = combine(header.ts.tv_sec, header.ts.tv_usec)
				rtp_data_obj.delay_list.append(0.00)
				delay = 0

			#Transformamos la diferencia de los timestamps de microsegundos a segundos
			difference_in_sec = (difference*125)/1000000
			#Calculamos la diferencia del tiempo de llegada del paquete actual con el anterior
			inter_arrival_time = delay - difference_in_sec

			#Esta parte del codigo se encarga de calcular el jitter
			if rtp_data_obj.jitter_prev_packet != -1:
				jitter = rtp_data_obj.jitter_prev_packet + (abs(inter_arrival_time) - rtp_data_obj.jitter_prev_packet) / 16
				rtp_data_obj.jitter_prev_packet = jitter
				if mark == 0:
					rtp_data_obj.jitter_list.append(round(jitter*1000, 2))
			else:
				jitter = 0
				rtp_data_obj.jitter_list.append(jitter)
				rtp_data_obj.jitter_prev_packet = 0


			#Este bloque de codigo se encarga de introducir los silencios, perdidas y payloads de las llamadas en listas en forma de bytes
			#Si se ha detectado un silencio, este if introduce tantos silencios como el tamaño del silencio
			if is_silence:
				byte_array = bytearray.fromhex("D5"*int(silence_size))
				for byte in byte_array:
					rtp_data_obj.rtp_audio_list.append(byte.to_bytes(1, "little"))

			#Este if se encarga de introducir tantos silencios como el tamaño del paquete por el numero de paquetes perdidos si se detectan perdidas
			if is_lost:
				#print("IS LOST: silence_size:", silence_size, "seq_difference:", seq_difference)
				byte_array = bytearray.fromhex("D5"*int(silence_size*(seq_difference - 1)))
				for byte in byte_array:
					rtp_data_obj.rtp_audio_list.append(byte.to_bytes(1, "little"))

			#Introducimos el payload del paquete actual en la lista	
			rtp_data_obj.rtp_audio_list.append(payload)

			#Guardamos el instante de tiempo en el que se recibe el paquete en la variable global
			last_packet_received = combine(header.ts.tv_sec, header.ts.tv_usec)

		else:
			#print("NI SIP NI RTP")
			return

	elif transport_protocol == 1 or transport_protocol == 58:
		#print("PAQUETE CON PROTOCOLO ICMPv4 o ICMPv6", NUM_PAQUETE)
		return

	return

if __name__ == "__main__":

	parser = argparse.ArgumentParser(description='Captura tráfico de una traza SIP para extraer información',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False, help='Fichero pcap a abrir')
	args = parser.parse_args()

	if args.tracefile is False:
		parser.print_help()
		sys.exit(-1)

	signal.signal(signal.SIGINT, signal_handler)

	handle = None
	errbuf = bytearray()

	handle = pcap_open_offline(args.tracefile, errbuf)

	timer = Monitoring_Timer(60.0, garbage_collector)
	timer.start()

	sem = threading.Semaphore(1)

	print("Comienza la ejecucion del programa...")

	ahora = time.time()
	
	ret = pcap_loop(handle, -1, procesa_paquete, None)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')

	print("Se han procesado {} paquetes.".format(NUM_PAQUETE))
	pcap_close(handle)

	timer.cancel()

	despues = time.time()

	print("Tiempo total ", despues-ahora)