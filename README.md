## SerialSniff

### Overview

`SerialSniff` is a simple tool to monitor communications between a host software and a serial device.


### Usage

#### Command Line

Executing `python3 serialsniff.py -h` yields the usage instructions:

```
user@pc:serialsniff$ python3 serialsniff.py -h
usage: serialsniff.py [-h] [--incoming] [--outgoing] [--file FILE]
                      [--columns COLUMNS]
                      port baudrate

positional arguments:
  port                  serial port to sniff
  baudrate              baudrate of the serial port to sniff

optional arguments:
  -h, --help            show this help message and exit
  --incoming, -i        sniff incoming (from host to serial device) transfers
  --outgoing, -o        sniff outgoing (from serial device to host) transfers
  --file FILE, -f FILE  file to write the sniffed transfers to
  --columns COLUMNS     how many columns of characters to display per line
```
##### Notes

- When `--incoming` and `--outgoing` are both specified, the tool sniffs transfers in both directions. These directions use the serial device as the reference: "incoming" means transfers going to the serial device, "outgoing" means transfers from the serial device. If both are **not** are specified, the tool does an outgoing sniff.
- When `--file` is specified, the sniffed transfers are written to a file, besides being displayed on the terminal.
- By default, `--columns` is set to 8.

##### Example

The example below performs a bidirectional sniff of an AT-based modem, with the output written to a file named `test.txt`.

```
user@pc:serialsniff$ python3 serialsniff.py  "/dev/ttyUSB2" 115200 -io -f test.txt
SerialSniff

port:           /dev/ttyUSB2
baudrate:       115200
proxy:          /dev/pts/6


[INCOMING] 21:26:50.858171 (1 bytes)    A                                41


[INCOMING] 21:26:51.001900 (1 bytes)    T                                54


[INCOMING] 21:26:51.185892 (1 bytes)    \r                               0d


[OUTGOING] 21:26:51.193577 (6 bytes)    \r\nOK\r\n                       0d 0a 4f 4b 0d 0a

```

In this example, the modem has the serial port `/dev/ttyUSB2`. Instead of connecting the terminal program used to send commands and recieve
responses from the modem directly to `/dev/ttyUSB2`, it is connected to the proxy port `/dev/pts/6`.

#### Python

`serialsniff.py` contains a `SerialSniff` class used to implement the command-line functionality; which can be used in your own Python programs.

```python
sniff = SerialSniff(args.port,                          # serial port to sniff
                    args.baudrate,                      # baudrate of the serial port to sniff
                    SerialSniff.Mode.BIDIRECTIONAL)     # direction to sniff

sniff.start()                                           # start sniffing
sniff.join()                                            # wait indefinitely
```

Some important members of the `SerialSniff` class are as follows:

```python
sniff.proxy                                             # proxy port where the host program should be connected instead
sniff.data_queue                                        # Python queue where incoming/outgoing data is put whenever available
```

### Limitations

- Uses pseudoterminals - might not work on Windows
- No hardware flow control, or other serial signal lines.
