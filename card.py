import argparse, os
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.Exceptions import *

READER_NAMES = ['HID Global OMNIKEY', 'Reader PICC']
# MIFARE Classic commands
CMD_GET_PURSE_FILE = [0xFF, 0xB1, 0x00, 0x08, 0x04]
CMD_AUTH_BLOCK = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x08, 0x60, 0x00]  # block no. on 3rd last hex, block 8
CMD_AUTH_BLOCK_LAST_TRANSACTION = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x09, 0x60, 0x00]  # block no. on 3rd last hex block 9
CMD_LOAD_KEY = [0xFF, 0x82, 0x20, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
CMD_GET_TRANSACTION_LOG = [0x90, 0x32, 0x03, 0x00, 0x01, 0x00, 0x00]
CMD_WRITE_INIT = [0xFF, 0xD6, 0x00, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x08, 0xF7, 0x08, 0xF7]  # block 8
CMD_WRITE_INIT_TRANSACT = [0xFF, 0xD6, 0x00, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00]  # block 9
STATION_NAMES = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']
MAX_FARE_LOOKUP = {'A': 680, 'B': 590, 'C': 510, 'D': 480, 'E': 380, 'F': 420, 'G': 570, 'H': 680}
FARE_LOOKUP = {'A': 90, 'B': 80, 'C': 30, 'D': 100, 'E': 120, 'F': 150, 'G': 110, 'H': 0}
REVERSE_FARE_LOOKUP = {'H': 110, 'G': 150, 'F': 120, 'E': 100, 'D': 30, 'C': 80, 'B': 90, 'A': 0}


def get_station_letter_textfile_value():
    """ Returns the station letter found in the text document, else create a blank text file. Includes edge cases regarding file and invalid station names. """
    try:
        with open("Bus_Station.txt", 'r') as station_doc:
            station = station_doc.read()
            if station.upper() in STATION_NAMES:
                return station
            else:
                exit("Unable to gather station name.")
    except FileNotFoundError:
        with open("Bus_Station.txt", 'x'):
            pass
        exit("File either unreadable or not found. Creating file, please ensure it contains a station name A to H.")


def get_topup_textfile_value():
    """ Returns the top value found in the text document, else create a blank text file. Includes edge cases regarding file and invalid characters. """
    try:
        with open("top_up_value.txt", 'r') as top_up_doc:
            top_up = top_up_doc.read()
            if top_up.isdigit():
                return int(top_up)
    except FileNotFoundError:
        with open("top_up_value.txt", 'x'):
            pass
        exit("File either unreadable or not found. Creating file, please ensure it contains a top up value integer.")


def get_max_tap_in_fare_value(station):
    """ Return the maximum fare to be charged based on the station. """
    fare = MAX_FARE_LOOKUP[station]
    return fare


def find_used_fare(source_station, dest_station):
    """ Gets and return the fare value used based on source to destination stations. """
    fare = 0
    if source_station == dest_station:
        fare = MAX_FARE_LOOKUP[source_station]
        return fare
    if source_station < dest_station:
        stations = list(FARE_LOOKUP)
        source_index = stations.index(source_station)
        dest_index = stations.index(dest_station)
        for station in stations[source_index: dest_index]:
            fare += FARE_LOOKUP[station]
        return fare
    if dest_station < source_station:
        stations = list(REVERSE_FARE_LOOKUP)
        source_index = stations.index(source_station)
        dest_index = stations.index(dest_station)
        for station in stations[source_index: dest_index]:
            fare += REVERSE_FARE_LOOKUP[station]
        return fare


def tap_out_fare_refund_value(source_station, dest_station):
    """ Get the refund value needed based on provided stations. """
    debited = get_max_tap_in_fare_value(source_station)
    used = find_used_fare(source_station, dest_station)
    refund = debited - used
    return refund


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
    # for each in response_list[2:5]:
    for each in response_list:
        cepas_value += each
    cepas_value = '0x' + cepas_value
    print(f'Card value: ${eval(cepas_value) / 100:.2f}')


def initialise(reader):
    connection = reader.createConnection()
    try:
        connection.connect()
        send_apdu(connection, CMD_LOAD_KEY)  # Loading Key A
        send_apdu(connection, CMD_AUTH_BLOCK)  # Authenticating Block 8
        send_apdu(connection, CMD_WRITE_INIT)  # Write 0 in value format for block 8
        response, status_code = send_apdu(connection, CMD_GET_PURSE_FILE)  # Getting Purse Value
        print(response, status_code)
        print_cepas_value(response)  # Printing value of purse
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


def check_balance(reader):
    """ Read value of eight sector. """
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
        exit()
    return response


def top_up(reader, value):
    CMD_TOP_UP_TEMPLATE = [0xFF, 0xD7, 0x00, 0x08, 0x05, 0x01]
    hex_value = hex(value)
    str(hex_value)
    pad_len = 10 - len(hex_value)
    if pad_len > 0:
        hex_value = hex_value[2:]
        new_value = pad_len * '0' + hex_value
        CMD_TOP_UP_TEMPLATE.append(int(new_value[0:2], 16))
        CMD_TOP_UP_TEMPLATE.append(int(new_value[2:4], 16))
        CMD_TOP_UP_TEMPLATE.append(int(new_value[4:6], 16))
        CMD_TOP_UP_TEMPLATE.append(int(new_value[6:8], 16))
        connection = reader.createConnection()
        try:
            connection.connect()
            response, status_code = send_apdu(connection, CMD_LOAD_KEY)
            response, status_code = send_apdu(connection, CMD_AUTH_BLOCK)
            response, status_code = send_apdu(connection, CMD_TOP_UP_TEMPLATE)
        except NoCardException:
            print("No smart card found.")
            return None
        except CardConnectionException:
            print("Card reader cannot be found, please check connection of card reader.")
            return None
        if status_code == "SW1: 90, SW2: 00":
            # Extract UID from the response
            print(f"Top up successful. ${value / 100:.2f} added.")
        else:
            print("Failed to retrieve UID.")
            exit()


def get_topup_input(max_value):
    valid_value = False
    print(f"The maximum value you can top up is {max_value} cents.")
    if max_value <= 0:
        print("You have hit the max top-up value. Returning to main menu.")
        valid_value = True
        return None
    while not valid_value:
        top_up_value = input("Please enter the topup value you like in cents or 0 to cancel: ")
        if top_up_value.isdigit():
            top_up_value = int(top_up_value)
            if top_up_value < 0:
                pass
            elif int(top_up_value) > max_value:
                print(f"You cannot top up more than {max_top_up_value} cents.")
            else:
                valid_value = True
    return top_up_value


def get_station_input():
    valid_station_input = False
    chosen_station = input("Please enter the station you wish to use: ")
    if station in STATION_NAMES:
        return station
    else:
        return None


def max_top_up_value(reader):
    current_value = check_balance(reader)
    current_value = current_value.split(' ')
    for each in current_value:
        each = '0x' + each
    value_in_hex = ''
    for each in current_value:
        value_in_hex += each
    value_in_hex = '0x' + value_in_hex
    max_value = 4294967295 - eval(value_in_hex)
    return max_value


def main():
    reader = init_reader()

    print("\nWelcome to the Override UI menu \nPlease Select your choice")
    while True:
        print("=" * 30)
        print("Choice 1: Initialize card as new")
        print("Choice 2: Top-up card (any value)")
        print("Choice 3: Check Balance")
        print("Choice 4: Tap-in self-defined Station")
        print("Choice 5: Tap-out self-defined Station")
        print("Choice 6: View last debit/refund transaction")
        print("Choice 7: Exit \n")
        userChoice = int(input("Enter your choice: "))
        print("")
        match userChoice:
            case 1:
                initialise(reader)
            case 2:
                max_value_for_top = max_top_up_value(reader)
                value = get_topup_input(max_value_for_top)
                if value:
                    top_up(reader, value)
            case 3:
                check_balance(reader)
            case 4:
                tap_in_station = get_station_input()
                if tap_in_station:
                    pass
                else:
                    print("Invalid station name provided.")
            case 5:
                tap_out_station = get_station_input()
                if tap_out_station:
                    pass
                else:
                    print("Invalid station name provided.")
            case 6:
                pass
            case 7:
                print("Thank you for using CPS Smart Card!")
                break
            case _:
                print("Invalid Input, please try again")


parser = argparse.ArgumentParser(description="Perform actions based on input arguments.")
group = parser.add_mutually_exclusive_group()
group.add_argument("-n", "--new", action="store_true", help="Initialize card as new.")
group.add_argument("-u", "--topup", action="store_true",
                   help="Top up the card with the number of cents provided in text file.")
group.add_argument("-b", "--balance", action="store_true", help="Check Balance.")
group.add_argument("-i", "--tap_in", action="store_true", help="Tap out of station based on text file.")
group.add_argument("-o", "--tap_out", action="store_true", help="Tap into station based on text file.")
group.add_argument("-t", "--transactions", action="store_true", help="View last paid/refund transactions.")
group.add_argument("-c", "--CLI", action="store_true", help="Run CLI Interface for special override menu.")
args = parser.parse_args()

if args.balance:
    reader = init_reader()
    check_balance(reader)

if args.tap_in:
    station = get_station_letter_textfile_value()
    fare = MAX_FARE_LOOKUP[station]

if args.tap_out:
    station = get_station_letter_textfile_value()

if args.CLI:
    main()

main()
