import abc
import queue
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

BUFFER_SIZE = 1024
LOCAL_ADDR = ('192.0.0.8', 1027)


def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(LOCAL_ADDR)
    return sock.getsockname()[0]


class BaseServer:
    def __init__(self, port):
        self._port = port
        self._sock = self._make_socket(1000000)
        self._max_workers = 5
        self._answer_queue = queue.Queue()

    @abc.abstractmethod
    def _client_req_handler(self, addr, packet):
        pass

    @abc.abstractmethod
    def _server_resp_handler(self, packet):
        pass

    @staticmethod
    def _make_socket(timeout=2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        return sock

    @staticmethod
    def shutdown():
        print('\nShutdown...')
        sys.exit()

    def run(self):
        self._sock.bind(('', self._port))
        pool = ThreadPoolExecutor(self._max_workers)
        print(f'Started at {get_local_ip()} : {self._port}')
        while True:
            try:
                resp, addr = self._sock.recvfrom(BUFFER_SIZE)
                pool.submit(self.process_packet, resp, addr)
            except KeyboardInterrupt:
                self.shutdown()
                break
            except Exception:
                pass

        self._sock.close()

    def process_packet(self, packet, addr):
        pack_type = self.get_packet_type(packet)

        if pack_type == 0:
            self._client_req_handler(addr, packet)
        else:
            raise Exception('Invalid packet')

    @staticmethod
    def get_packet_type(packet):
        return packet[3] >> 7
