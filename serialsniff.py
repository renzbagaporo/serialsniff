import serial
import os
import time
import enum
import threading
import select
import queue
import collections
import argparse

from abc import ABC, abstractmethod
from datetime import datetime


class SerialSniff(threading.Thread):

    DEFAULT_TIMEOUT = 1000
    DEFAULT_MAX_DATA_LEN = 1024

    class Mode(enum.Enum):
        INCOMING_ONLY = 1
        OUTGOING_ONLY = 2
        BIDIRECTIONAL = 3

    class Direction(enum.Enum):
        INCOMING = 1
        OUTGOING = 2

    class Data:
        def __init__(self, data, direction):
            self.data = data
            self.time = datetime.now()
            self.direction = direction

    def _output_data_to_queue(self, data, direction):
        if self.mode == SerialSniff.Mode.BIDIRECTIONAL or self.mode == direction:
            self.data_queue.put(SerialSniff.Data(data, direction))

    def _incoming_data_thread_fn(self):
        # master -> uart, SerialSniff.Direction.TO_SERIAL
        poll = select.poll()
        poll.register(self._pty_master)

        while True:
            events = poll.poll()
            for fd, event_type in events:
                data = os.read(self._pty_master, self._max_data_len)
                self._output_data_to_queue(data, SerialSniff.Direction.INCOMING)
                self._serial.write(data)

    def _outgoing_data_thread_fn(self):
        while True:
            data = self._serial.read(self._max_data_len)
            if data:
                self._output_data_to_queue(data, SerialSniff.Direction.OUTGOING)
                os.write(self._pty_master, data)

    def __init__(self, port, baud, mode, timeout=DEFAULT_TIMEOUT, max_data_len=DEFAULT_MAX_DATA_LEN):
        self._pty_master, self._pty_slave = os.openpty()

        self.port = port
        self.proxy = os.ttyname(self._pty_slave)
        self.baud = baud

        self.timeout = timeout
        self.timeout_s = (1 / baud) * timeout

        self._max_data_len = max_data_len

        self.mode = mode

        self._serial = serial.Serial(self.port, self.baud, rtscts=True, dsrdtr=True, timeout=self.timeout_s)
        self._incoming_data_thread = threading.Thread(target=self._incoming_data_thread_fn, daemon=True)
        self._outgoing_data_thread = threading.Thread(target=self._outgoing_data_thread_fn, daemon=True)

        self.data_queue = queue.Queue()

    def start(self):
        self._incoming_data_thread.start()
        self._outgoing_data_thread.start()

    def join(self):
        self._incoming_data_thread.join()
        self._outgoing_data_thread.join()

    def cleanup(self):
        self._serial.close()
        os.close(self._pty_slave)
        os.close(self._pty_master)

def sniffer_log_thread_fn(data_queue, columns):
    while True:
        data = data_queue.get()

        direction = "[INCOMING]" if data.direction == SerialSniff.Direction.INCOMING else "[OUTGOING]"
        timestamp = data.time.strftime("%H:%M:%S.%f")
        data_len = len(data.data)

        details = "{} {} ({} bytes)".format(direction, timestamp, data_len)
        print(details, end='')

        start = 0
        data_bytes = data.data[start:start+columns]

        while data_bytes:
            data_str = str(data_bytes)[2:-1]

            data_hex_str = data_bytes.hex()
            data_hex_str = ' '.join(a+b for a,b in zip(data_hex_str[::2], data_hex_str[1::2]))

            print("\t{} {}".format(data_str.ljust(columns * 4, ' '), data_hex_str)) # 4 is worst case, ex: ctrl-z = \x1a

            start = start + columns
            data_bytes = data.data[start:start+columns]

            print(" " * len(details), end='')

        print("\r\n")

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("port", type=str)
        parser.add_argument("baudrate", type=int)
        parser.add_argument("--outgoing", action="store_true")
        parser.add_argument("--incoming", action="store_true")
        parser.add_argument("--columns", type=int, default=8)

        args = parser.parse_args()

        if args.incoming and args.outgoing:
            sniff = SerialSniff(args.port, args.baudrate, SerialSniff.Mode.BIDIRECTIONAL)
        elif args.incoming:
            sniff = SerialSniff(args.port, args.baudrate, SerialSniff.Mode.INCOMING_ONLY)
        else: # outgoing, or default - sniff FROM_SERIAL
            sniff = SerialSniff(args.port, args.baudrate, SerialSniff.Mode.OUTGOING_ONLY)

        print("SerialSniff\r\n")
        print("port:\t\t" + sniff.port)
        print("baudrate:\t" + str(sniff.baud))
        print("proxy:\t\t" + sniff.proxy)

        print("\r\n")

        sniffer_log_thread = threading.Thread(target=sniffer_log_thread_fn, args=(sniff.data_queue, args.columns), daemon=True)

        sniffer_log_thread.start()
        sniff.start()

        sniff.join()
        sniffer_log_thread.join()
    except KeyboardInterrupt:
        sniff.cleanup()

if __name__ == "__main__":
    main()

