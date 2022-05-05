from threading import Timer


#Estructura de datos usada para almacenar los datos de una llamada
class Call(object):
    __slots__ = ("call_id", "froom", "to", "rtp_ip_dest", "rtp_port_dest", "rtp_ip_src", "rtp_port_src")


#Estructura de datos usada para almacenar los datos a reemplazar cuando se produce una renegociacion
class Renegotiation(object):
    __slots__ = ("rtp_ip_dest", "rtp_port_dest", "rtp_ip_src", "rtp_port_src")


#Estructura de datos usada para almacenar los parametros RTP del sentido de una llamada
class Call_Data(object):
    __slots__ = ("call_id", "rtp_ip_src", "rtp_port_src", "rtp_ip_dest", "rtp_port_dest", "seq_num_prev_packet", "tmstmp_prev_packet",
                 "frames_prev_packet", "time_difference", "num_total_packets", "num_lost_packets", "arrival_prev_packet", "delay_list",
                 "jitter_prev_packet", "jitter_list", "ssrc", "payload", "rtp_audio_list", "time_begin", "time_end")


#Estructura de datos que guarda la informacion de una llamada que va a ser cancelada
class Cancel_Data(object):
    __slots__ = ("call_id", "rtp_ip_dest", "rtp_port_dest", "error_message", "error_code")


class Monitoring_Timer():

    def __init__(self, time, function):
        self.time = time
        self.function = function
        self.thread = Timer(self.time, self.exec_function)

    def exec_function(self):
        self.function()
        self.thread = Timer(self.time, self.exec_function)
        self.thread.start()

    def start(self):
        self.thread.start()

    def cancel(self):
        self.thread.cancel()

