from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.Exceptions import *

READER_NAMES = ['HID Global OMNIKEY', 'Reader PICC']


def send_apdu(connection, apdu_cmd):
    data, sw1, sw2 = connection.transmit(apdu_cmd)
    response = toHexString(data)
    status_code = "SW1: {:02X}, SW2: {:02X}".format(sw1, sw2)
    return response, status_code


def init_reader():
    # Check reader
    card_readers = readers()

    if not card_readers:
        print("No smart card readers found.")
        exit()
    for reader in card_readers:
        print(f'Card reader detected: {str(reader).rjust(45)}')
    for each in card_readers:
        if any(defined_reader in str(each) for defined_reader in READER_NAMES):
            print(f'Connected to {each}.')
            return each
    exit('No compatible readers found from reader list. Closing the program.')


# MIFARE Classic commands
CMD_GET_PURSE_FILE = [0xFF, 0xB1, 0x00, 0x04, 0x04]
cmd_inc = [0xFF, 0xD4, 0x00, 0x04, 0x04, 0x04, 0x01, 0x00, 0x00, 0x00]

CMD_AUTH_BLOCK = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x60, 0x00]  # block no. on 3rd last hex, block 8
CMD_AUTH_BLOCK_LAST_TRANSACTION = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x05, 0x60, 0x00]  # block no. on 3rd last hex block 9
CMD_LOAD_KEY = [0xFF, 0x82, 0x20, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
CMD_GET_TRANSACTION_LOG = [0x90, 0x32, 0x03, 0x00, 0x01, 0x00, 0x00]
CMD_WRITE_INIT = [0xFF, 0xD6, 0x00, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x08, 0xF7, 0x08, 0xF7]  # block 8
CMD_WRITE_INIT_TRANSACT = [0xFF, 0xD6, 0x00, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00]  # block 9

reader = init_reader()
connection = reader.createConnection()
connection.connect()
send_apdu(connection, CMD_LOAD_KEY)
send_apdu(connection, CMD_AUTH_BLOCK)
a,b = send_apdu(connection, cmd_inc)
print(a,b)
