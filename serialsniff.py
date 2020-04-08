# Copyright (c) 2020 Renz Christian Bagaporo
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import serial
import os
import threading
import select
import queue
import argparse

from enum import IntEnum
from datetime import datetime


class SerialSniff(threading.Thread):

    DEFAULT_TIMEOUT = 1000
    DEFAULT_MAX_DATA_LEN = 1024

    class Mode(IntEnum):
        INCOMING_ONLY = 1
        OUTGOING_ONLY = 2
        BIDIRECTIONAL = 3

    class Direction(IntEnum):
        INCOMING = 1
        OUTGOING = 2

    class Data:
        def __init__(self, data, direction):
            self.data = data
            self.time = datetime.now()
            self.direction = direction

    def _output_data_to_queue(self, data, direction):
        if self.mode == SerialSniff.Mode.BIDIRECTIONAL or \
           int(self.mode) == int(direction):
            self.data_queue.put(SerialSniff.Data(data, direction))

    def _incoming_data_thread_fn(self):
        # master -> uart, SerialSniff.Direction.TO_SERIAL
        poll = select.poll()
        poll.register(self._pty_master)

        while True:
            events = poll.poll()
            for fd, event_type in events:
                data = os.read(self._pty_master, self._max_data_len)
                self._output_data_to_queue(data,
                                           SerialSniff.Direction.INCOMING)
                self._serial.write(data)

    def _outgoing_data_thread_fn(self):
        while True:
            data = self._serial.read(self._max_data_len)
            if data:
                self._output_data_to_queue(data,
                                           SerialSniff.Direction.OUTGOING)
                os.write(self._pty_master, data)

    def __init__(self, port, baud, mode, timeout=DEFAULT_TIMEOUT,
                 max_data_len=DEFAULT_MAX_DATA_LEN):
        self._pty_master, self._pty_slave = os.openpty()

        self.port = port
        self.proxy = os.ttyname(self._pty_slave)
        self.baud = baud

        self.timeout = timeout
        self.timeout_s = (1 / baud) * timeout

        self._max_data_len = max_data_len

        self.mode = mode

        self._serial = serial.Serial(self.port,
                                     self.baud,
                                     rtscts=True,
                                     dsrdtr=True,
                                     timeout=self.timeout_s)
        self._incoming_data_thread = threading.Thread(
                                    target=self._incoming_data_thread_fn,
                                    daemon=True
                                    )
        self._outgoing_data_thread = threading.Thread(
                                    target=self._outgoing_data_thread_fn,
                                    daemon=True
                                    )

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


def output(s, e=None, f=None):
    if e is not None:
        print(s, end=e)
    else:
        print(s)

    if f:
        f.write(s + ("\r\n" if e is None else e))
        f.flush()


def sniffer_log_thread_fn(data_queue, columns, out_file=None):
    while True:
        data = data_queue.get()

        direction = "[INCOMING]" \
                    if data.direction == SerialSniff.Direction.INCOMING \
                    else "[OUTGOING]"
        timestamp = data.time.strftime("%H:%M:%S.%f")
        data_len = len(data.data)

        details = "{} {} ({} bytes)".format(direction, timestamp, data_len)
        output(details, '', f=out_file)

        start = 0
        data_bytes = data.data[start:start+columns]

        while data_bytes:
            data_str = str(data_bytes)[2:-1]

            data_hex_str = data_bytes.hex()
            data_hex_str = ' '.join(a+b for a, b in zip(data_hex_str[::2],
                                                        data_hex_str[1::2]))

            # 4 is worst case, ex: ctrl-z = \x1a
            output("\t{} {}".format(data_str.ljust(columns * 4, ' '),
                                    data_hex_str), f=out_file)

            start = start + columns
            data_bytes = data.data[start:start+columns]

            output(" " * len(details), '', f=out_file)

        output("\r\n", f=out_file)


def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("port", type=str,
                            help="serial port to sniff")
        parser.add_argument("baudrate", type=int,
                            help="baudrate of the serial port to sniff")
        parser.add_argument("--incoming", "-i", action="store_true",
                            help="sniff incoming (from host to serial device) \
                            transfers")
        parser.add_argument("--outgoing", "-o", action="store_true",
                            help="sniff outgoing (from serial device to host) \
                            transfers")
        parser.add_argument("--file", "-f", type=argparse.FileType("w"),
                            help="file to write the sniffed transfers to")
        parser.add_argument("--columns", type=int, default=8,
                            help="how many columns of characters to display \
                            per line")

        args = parser.parse_args()

        if args.incoming and args.outgoing:
            sniff = SerialSniff(args.port,
                                args.baudrate,
                                SerialSniff.Mode.BIDIRECTIONAL)
        elif args.incoming:
            sniff = SerialSniff(args.port,
                                args.baudrate,
                                SerialSniff.Mode.INCOMING_ONLY)
        else:  # outgoing, or default - sniff FROM_SERIAL
            sniff = SerialSniff(args.port,
                                args.baudrate,
                                SerialSniff.Mode.OUTGOING_ONLY)

        output("SerialSniff\r\n", f=args.file)
        output("port:\t\t" + sniff.port, f=args.file)
        output("baudrate:\t" + str(sniff.baud), f=args.file)
        output("proxy:\t\t" + sniff.proxy, f=args.file)

        output("\r\n", f=args.file)

        sniffer_log_thread = threading.Thread(target=sniffer_log_thread_fn,
                                              args=(sniff.data_queue,
                                                    args.columns,
                                                    args.file),
                                              daemon=True)

        sniffer_log_thread.start()
        sniff.start()

        sniff.join()
        sniffer_log_thread.join()
    except KeyboardInterrupt:
        sniff.cleanup()


if __name__ == "__main__":
    main()
