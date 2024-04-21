import argparse, os
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.Exceptions import *

READER_NAMES = ['HID Global OMNIKEY', 'Reader PICC']
# MIFARE Classic commands
CMD_GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
CMD_GET_PURSE_FILE = [0xFF, 0xB0, 0x00, 0x04, 0x00]
CMD_AUTH_BLOCK = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x60, 0x00]
CMD_LOAD_KEY = [0xFF, 0x82, 0x00, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
CMD_GET_TRANSACTION_LOG = [0x90, 0x32, 0x03, 0x00, 0x01, 0x00, 0x00]
CMD_WRITE_INIT = [0xFF, 0xD6, 0x00, 0x08, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                  0x08, 0xF7, 0x08, 0xF7]


def send_apdu(connection, apdu_cmd):
    data, sw1, sw2 = connection.transmit(apdu_cmd)
    response = toHexString(data)
    status_code = "SW1: {:02X}, SW2: {:02X}".format(sw1, sw2)
    return response, status_code


def print_cepas_value(response):
    response_list = response.split(' ')
    for each in response_list:
        each = '0x' + each
    cepas_value = ''
    for each in response_list[2:5]:
        cepas_value += each
    cepas_value = '0x' + cepas_value
    print(f'CEPAS value: ${eval(cepas_value) / 100}')


def initialise(reader):
    connection = reader.createConnection()
    try:
        connection.connect()
        send_apdu(connection, CMD_LOAD_KEY)  # Loading Key
        send_apdu(connection, CMD_AUTH_BLOCK)  # Authenticating Block 4
        response, status_code = send_apdu(connection, CMD_GET_PURSE_FILE)  # Getting Purse information
        print(response)  # Printing value of purse
    except NoCardException:
        print("No smart card found.")
        return None
    except CardConnectionException:
        print("Card reader cannot be found, please check connection of card reader.")
        return None
    return "Initialised"


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


def checkBalance(reader):
    connection = reader.createConnection()
    try:
        connection.connect()
        response, status_code = send_apdu(connection, CMD_LOAD_KEY)
        response, status_code = send_apdu(connection, CMD_AUTH_BLOCK)
        response, status_code = send_apdu(connection, CMD_GET_PURSE_FILE)
    except NoCardException:
        print("No smart card found.")
        return None
    except CardConnectionException:
        print("Card reader cannot be found, please check connection of card reader.")
        return None
    if status_code == "SW1: 90, SW2: 00":
        # Extract UID from the response
        print_cepas_value(response)
    else:
        print("Failed to retrieve UID.")
    balance = 0
    message = "Your Card Balance is ${balance}".format(balance=balance)
    return message


def main():
    reader = init_reader()
    # print_atr(reader)

    print("\nWelcome to the Override UI menu \nPlease Select your choice")
    while True:
        print("=" * 30)
        print("Choice 1: Initialize card as new")
        print("Choice 2: Top-up card (any value)")
        print("Choice 3: Check Balance")
        print("Choice 4: Tap-in self-defined Station")
        print("Choice 5: Tap-out self-defined Station")
        print("Choice 6: View Transaction Log")
        print("Choice 7: Exit \n")
        userChoice = int(input("Enter your choice: "))
        print("")
        match userChoice:
            case 1:
                initialise(reader)
            case 2:
                pass
            case 3:
                checkBalance(reader)
            case 4:
                pass
            case 5:
                pass
            case 6:
                pass
            case 7:
                print("Thank you for using CPS Smart Card!")
                break
            case _:
                print("Invalid Input, please try again")


parser = argparse.ArgumentParser(description="Perform actions based on input arguments.")
group = parser.add_mutually_exclusive_group()
group.add_argument("-i", "--tap_in", action="store_true", help="Tap out of station based on text file.")
group.add_argument("-o", "--tap_out", action="store_true", help="Tap into station based on text file.")
group.add_argument("-t", "--transactions", action="store_true", help="View past transactions.")
group.add_argument("-u", "--topup", action="store_true",
                   help="Top up the card with the number of cents provided in text file.")
group.add_argument("-c", "--CLI", action="store_true",
                   help="Run CLI Interface for special manual override.")
args = parser.parse_args()

if args.CLI:
    main()