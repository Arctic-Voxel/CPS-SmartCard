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
CMD_WRITE_INIT=[0xFF, 0xD6, 0x00, 0x08, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x08, 0xF7, 0x08, 0xF7]

# Function to send APDU commands to the card
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


def print_transaction_log(response):
    response_list = response.split(' ')
    for each in response_list:
        each = '0x' + each
    # Blocks of 16 bytes (1 2amount 3date 8 user)


def main():
    # Get all available smart card readers
    card_readers = readers()

    if not card_readers:
        print("No smart card readers found.")
        return

    print("Available smart card readers:")
    for reader in card_readers:
        print(reader)

    # Select the reader you want to connect to....
    reader = card_readers[1]

    # Connect to the selected reader
    connection = reader.createConnection()
    connection.connect()

    # Send command to get UID
    response, status_code = send_apdu(connection, CMD_GET_PURSE_FILE)

    if status_code == "SW1: 90, SW2: 00":
        # Extract UID from the response
        uid = response[:-4]
        print("Response:", uid)
        print_cepas_value(response)
    else:
        print("Failed to retrieve UID.")

    print("\nSEND PURSE REQUEST")
    response, status_code = send_apdu(connection, CMD_GET_TRANSACTION_LOG)

    if status_code == "SW1: 90, SW2: 00":
        # Extract UID from the response
        uid = response[:-4]
        print("Response:", uid)
        print_transaction_log(response)
    else:
        print("Failed to retrieve UID.")
    # Disconnect from the reader
    connection.disconnect()


# ====================================================== User Functions ===========================================================
def initialise(reader):
    connection = reader.createConnection()
    try:
        connection.connect()
        send_apdu(connection, CMD_LOAD_KEY)
        send_apdu(connection, CMD_AUTH_BLOCK)
        response, status_code = send_apdu(connection, CMD_GET_PURSE_FILE)
        print(response)
    except NoCardException:
        print("No smart card found.")
        return None
    except CardConnectionException:
        print("Card reader cannot be found, please check connection of card reader.")
        return None
    return "Initialised"


def topUp():
    balance = 0
    message = "Card Top Up Successful, balance is ${balance}".format(balance=balance)
    return message


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


def debitTransaction():
    amount = 0
    message = "Transaction successful, ${amount} has been deducted from your card".format(amount=amount)
    return message


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


def print_atr(reader):
    connection = reader.createConnection()
    try:
        connection.connect()
        print(toHexString(connection.getATR()))
    except NoCardException:
        print("No card found.")


# ======================================================= Main Function =============================================================
def main():
    reader = init_reader()
    # print_atr(reader)

    print("\nWelcome to the MIFARE UI \nPlease Select your choice")
    while True:
        print("=" * 30)
        print("Choice 1: Initialize card")
        print("Choice 2: Top-up card")
        print("Choice 3: Check Balance")
        print("Choice 4: Enter Station")
        print("Choice 5: Exit Station")
        print("Choice 6: View Transaction Log")
        print("")
        print("Choice 6: Exit \n")
        userChoice = int(input("Enter your choice: "))
        print("")
        match userChoice:
            case 1:
                initialise(reader)
            case 2:
                topUp()
            case 3:
                checkBalance(reader)
            case 4:
                debitTransaction()
            case 5:
                print("Thank you for using CPS Smart Card!")
                break
            case _:
                print("Invalid Input, please try again")


if __name__ == "__main__":
    main()
