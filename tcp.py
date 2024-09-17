import asyncio
import random
import time
from tcputils import *

ALFA = 0.125
BETA = 0.25


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
        flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return

        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4 * (flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao_seq_no = random.randint(0, 0xffff)
            conexao_ack_no = seq_no + 1
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, conexao_seq_no, conexao_ack_no)
            header = fix_checksum(
                make_header(dst_port, src_port, conexao_seq_no, conexao_ack_no, FLAGS_SYN | FLAGS_ACK), src_addr,
                dst_addr)
            self.rede.enviar(header, src_addr)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
            if (flags & FLAGS_FIN) == FLAGS_FIN:
                del self.conexoes[id_conexao]
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.seq_no = seq_no + 1
        self.ack_no = ack_no
        self.callback = None
        self.next_seq_num = self.seq_no
        self.unack_seg = []
        self.timer = None
        self.EstimatedRTT = 0
        self.DevRTT = 0
        self.SampleRTT = 0
        self.seg_timings = {}
        self.timeoutInterval = 1
        self.CWND = MSS
        self.unsent_data = []
        self.ackedBytes = 0

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if seq_no != self.ack_no:
            return

        if (flags & FLAGS_ACK) == FLAGS_ACK and ack_no > self.next_seq_num:
            dtFinal = time.time()

            self.ackedBytes += ack_no - self.next_seq_num
            ackedBytes = self.ackedBytes
            if self.ackedBytes >= self.CWND:
                self.CWND += MSS
                self.ackedBytes = 0

            if self.next_seq_num in self.seg_timings:
                self.SampleRTT = dtFinal - self.seg_timings[self.next_seq_num]
                del self.seg_timings[self.next_seq_num]
                if self.EstimatedRTT == 0:
                    self.EstimatedRTT = self.SampleRTT
                    self.DevRTT = self.SampleRTT / 2
                else:
                    self.EstimatedRTT = (1 - ALFA) * self.EstimatedRTT + ALFA * self.SampleRTT
                    self.DevRTT = (1 - BETA) * self.DevRTT + BETA * abs((self.SampleRTT - self.EstimatedRTT))

                self.timeoutInterval = self.EstimatedRTT + 4 * self.DevRTT
            self.next_seq_num = ack_no

            if self.unack_seg:
                while ackedBytes >= self.unack_seg[0][2]:
                    ackedBytes -= self.unack_seg[0][2]
                    del self.unack_seg[0]
                    if not self.unack_seg:
                        break

                if self.unack_seg:
                    self.start_timer()
                else:
                    self.timer.cancel()
            if self.unsent_data:
                self.enviar(self.unsent_data.pop(0))

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            payload = b''
            self.ack_no = self.ack_no + 1
        elif payload == b'':
            return
        self.callback(self, payload)
        self.ack_no = self.ack_no + len(payload)
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        self.servidor.rede.enviar(
            fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK), dst_addr, src_addr),
            src_addr)

    def _stop_timer(self):
        if self.timer is not None:
            self.timer.cancel()
        self.timer = None

    def start_timer(self):
        self._stop_timer()
        self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._timer)

    def _timer(self):
        if self.unack_seg:
            self.CWND = int((self.CWND / MSS) // 2) * MSS
            self.servidor.rede.enviar(self.unack_seg[0][0], self.unack_seg[0][1])
            key = self.seq_no - self.unack_seg[0][2]
            if key in self.seg_timings:
                del self.seg_timings[key]
            self.start_timer()

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        payload_size = len(dados)
        unacked_space = 0

        if self.unack_seg:
            for nya_segment in self.unack_seg:
                unacked_space += nya_segment[2]

        header = fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK), src_addr, dst_addr)
        if payload_size <= MSS:
            segmento = header + dados

            segmento = fix_checksum(segmento, src_addr, dst_addr)
            if (unacked_space + payload_size) <= self.CWND:
                self.servidor.rede.enviar(segmento, dst_addr)
                self.seg_timings[self.seq_no] = time.time()
                self.start_timer()
                self.unack_seg.append([segmento, src_addr, payload_size])
                self.seq_no += payload_size
            else:
                self.unsent_data.append(dados)
        else:
            segmento = header + dados[:MSS]

            segmento = fix_checksum(segmento, src_addr, dst_addr)
            if (unacked_space + MSS) <= self.CWND:
                self.servidor.rede.enviar(segmento, dst_addr)
                self.seg_timings[self.seq_no] = time.time()
                self.start_timer()
                self.unack_seg.append([segmento, src_addr, MSS])
                self.seq_no += MSS
                self.enviar(dados[MSS:])
            else:
                self.unsent_data.append(dados)

    def fechar(self):
        dst_addr, dst_port, src_addr, src_port = self.id_conexao
        header = make_header(src_port, dst_port, self.seq_no, self.ack_no, FLAGS_FIN)
        segmento = fix_checksum(header, src_addr, dst_addr)
        self.servidor.rede.enviar(segmento, dst_addr)
