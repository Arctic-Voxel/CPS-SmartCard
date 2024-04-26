import argparse
import calendar
import datetime as dt
import hmac
import time

import pytz
import struct
import base64
import hashlib
from smartcard.Exceptions import *
from smartcard.System import readers
from smartcard.util import toHexString

READER_NAMES = ['Reader PICC', 'ACR122']  # 'HID Global OMNIKEY' does not work, limited to only ACS readers
GMT_8 = pytz.timezone('Asia/Singapore')
# MIFARE Classic commands
CMD_LOAD_KEY = [0xFF, 0x82, 0x20, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
CMD_READ_VALUE_PURSE = [0xFF, 0xB1, 0x00, 0x08, 0x04]

# BLOCK 8 ==
CMD_AUTH_BLOCK = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x08, 0x61, 0x00]  # block no. on 3rd last hex, block 8
CMD_WRITE_INIT = [0xFF, 0xD6, 0x00, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                  0x08, 0xF7, 0x08, 0xF7]  # block 8

# BLOCK 9 ==
CMD_AUTH_BLOCK_LAST_TRANSACTION = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x09, 0x61,
                                   0x00]  # block no. on 3rd last hex, block 9
CMD_READ_TRANSACTION_LOG = [0xFF, 0xB0, 0x00, 0x09, 0x10]
CMD_WRITE_INIT_TRANSACTION_LOG = [0xFF, 0xD6, 0x00, 0x09, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]  # block 9

# BLOCK A (10) ==
CMD_AUTH_BLOCK_ROLL_BACK = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x0A, 0x61, 0x00]  # block 10
CMD_READ_BLOCK_ROLL_BACK = [0xFF, 0xB0, 0x00, 0x0A, 0x10]
CMD_WRITE_INIT_ROLL_BACK = [0xFF, 0xD6, 0x00, 0x0A, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00]  # block 62

STATION_NAMES = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']
MAX_FARE_LOOKUP = {'A': 680, 'B': 590, 'C': 510, 'D': 480, 'E': 380, 'F': 420, 'G': 570, 'H': 680}
FARE_LOOKUP = {'A': 90, 'B': 80, 'C': 30, 'D': 100, 'E': 120, 'F': 150, 'G': 110, 'H': 0}
REVERSE_FARE_LOOKUP = {'H': 110, 'G': 150, 'F': 120, 'E': 100, 'D': 30, 'C': 80, 'B': 90, 'A': 0}


def hotp(key, counter, digits=6, digest='sha1'):
    key = base64.b32decode(key.upper() + '=' * ((8 - len(key)) % 8))
    counter = struct.pack('>Q', counter)
    mac = hmac.new(key, counter, digest).digest()
    offset = mac[-1] & 0x0f
    binary = struct.unpack('>L', mac[offset:offset + 4])[0] & 0x7fffffff
    return str(binary)[-digits:].zfill(digits)


def totp(key, date, time_step=30, digits=6, digest='sha1'):
    return hotp(key, int(date / time_step), digits, digest)


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
    """ Sends the APDU to the APDU command and returns the APDU response. """
    data, sw1, sw2 = connection.transmit(apdu_cmd)
    response = toHexString(data)
    status_code = "SW1: {:02X}, SW2: {:02X}".format(sw1, sw2)
    return response, status_code


def print_cepas_value(response):
    """ Print the cepas-value response from the APDU. """
    response_list = response.split(' ')
    for each in response_list:
        each = '0x' + each
    cepas_value = ''
    # for each in response_list[2:5]:
    for each in response_list:
        cepas_value += each
    cepas_value = '0x' + cepas_value
    print(f'Card balance: ${eval(cepas_value) / 100:.2f}')


def process_value(response):
    response_list = response.split(' ')
    for each in response_list:
        each = '0x' + each
    cepas_value = ''
    # for each in response_list[2:5]:
    for each in response_list:
        cepas_value += each
    cepas_value = '0x' + cepas_value
    return eval(cepas_value) / 100


def initialise(reader):
    """ Initialise the card values. """
    connection = reader.createConnection()
    try:
        connection.connect()
        send_apdu(connection, CMD_LOAD_KEY)  # Loading Key A
        send_apdu(connection, CMD_AUTH_BLOCK)  # Authenticating Block 8
        send_apdu(connection, CMD_WRITE_INIT)  # Write 0 in value format for block 8
        response, status_code = send_apdu(connection, CMD_READ_VALUE_PURSE)  # Getting Purse Value
        time.sleep(0.05)
        send_apdu(connection, CMD_AUTH_BLOCK_LAST_TRANSACTION)  # Authenticating Block 9
        send_apdu(connection, CMD_WRITE_INIT_TRANSACTION_LOG)  # Write 0 in block format for Block 9
        time.sleep(0.05)
        send_apdu(connection, CMD_AUTH_BLOCK_ROLL_BACK)
        send_apdu(connection, CMD_WRITE_INIT_ROLL_BACK)

        print_cepas_value(response)  # Printing value of purse
    except NoCardException:
        print("No smart card found.")
        return None
    except CardConnectionException:
        print("Card reader cannot be found, please check connection of card reader.")
        return None
    return "Initialised"


def init_reader():
    """ Identify and select card readers. """
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
        send_apdu(connection, CMD_LOAD_KEY)
        send_apdu(connection, CMD_AUTH_BLOCK)
        response, status_code = send_apdu(connection, CMD_READ_VALUE_PURSE)
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


def debit(reader, value):
    """ Debit the card value. """
    cmd_debit = [0xFF, 0xD7, 0x00, 0x08, 0x05, 0x02]
    hex_value = hex(value)
    pad_len = 10 - len(hex_value)
    if pad_len > 0:
        hex_value = hex_value[2:]
        new_value = pad_len * '0' + hex_value
    else:
        new_value = hex_value
    cmd_debit.append(int(new_value[0:2], 16))
    cmd_debit.append(int(new_value[2:4], 16))
    cmd_debit.append(int(new_value[4:6], 16))
    cmd_debit.append(int(new_value[6:8], 16))
    connection = reader.createConnection()
    try:
        connection.connect()
        response, status_code = send_apdu(connection, CMD_LOAD_KEY)
        response, status_code = send_apdu(connection, CMD_AUTH_BLOCK)
        response, status_code = send_apdu(connection, cmd_debit)
    except NoCardException:
        print("No smart card found.")
        return None
    except CardConnectionException:
        print("Card reader cannot be found, please check connection of card reader.")
        return None
    if status_code == "SW1: 90, SW2: 00":
        # Extract UID from the response
        print(f"Debit successful. ${value / 100:.2f} deducted.")
    else:
        print("Failed to retrieve UID.")
        exit()


def top_up(reader, value):
    """ Top up card with stated value."""
    cmd_topup = [0xFF, 0xD7, 0x00, 0x08, 0x05, 0x01]
    hex_value = hex(value)
    pad_len = 10 - len(hex_value)
    if pad_len > 0:
        hex_value = hex_value[2:]
        new_value = pad_len * '0' + hex_value
    else:
        new_value = hex_value
    cmd_topup.append(int(new_value[0:2], 16))
    cmd_topup.append(int(new_value[2:4], 16))
    cmd_topup.append(int(new_value[4:6], 16))
    cmd_topup.append(int(new_value[6:8], 16))
    connection = reader.createConnection()
    try:
        connection.connect()
        response, status_code = send_apdu(connection, CMD_LOAD_KEY)
        response, status_code = send_apdu(connection, CMD_AUTH_BLOCK)
        response, status_code = send_apdu(connection, cmd_topup)
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
    """ Get top up input value with checks."""
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
    """ Get station input value with checks."""
    chosen_station = input("Please enter the station you wish to use: ")
    if chosen_station in STATION_NAMES:
        return chosen_station
    else:
        return None


def max_top_up_value(reader):
    """ Get max top up value based on current card value. """
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


def verify_transaction_history(reader):
    connection = reader.createConnection()
    try:
        connection.connect()
        send_apdu(connection, CMD_LOAD_KEY)
        send_apdu(connection, CMD_AUTH_BLOCK_LAST_TRANSACTION)
        transact_response, transact_status_code = send_apdu(connection, CMD_READ_TRANSACTION_LOG)
        send_apdu(connection, CMD_AUTH_BLOCK_ROLL_BACK)
        rollback_response, rollback_status_code = send_apdu(connection, CMD_READ_BLOCK_ROLL_BACK)

    except NoCardException:
        print("No smart card found.")
        return None
    except CardConnectionException:
        print("Card reader cannot be found, please check connection of card reader.")
        return None
    if transact_status_code == "SW1: 90, SW2: 00" and rollback_status_code == "SW1: 90, SW2: 00":
        print("Successful transaction.")
    else:
        print("Error retrieving transaction history and rollback value.")
        exit()
    # print(f"Transact: {transact_response}")
    # print(f"Rollback: {rollback_response}")
    if int(transact_response.replace(" ", ""), 16) == 0 and int(rollback_response.replace(" ", ""), 16) == 0:
        print("No transaction found.")
        return 'empty'
    hex_time = transact_response[18:29].replace(" ", "")
    dec_time = int(hex_time, 16)
    hex_totp = transact_response[30:38].replace(" ", "")
    dec_totp = int(hex_totp, 16)
    totp_challenge = totp('CPSSmartCard', dec_time, 30, 6, 'sha1')
    if int(totp_challenge) == dec_totp:
        print("TOTP challenge value is successful, transaction is valid.")
    else:
        print("TOTP challenge failed. Data has been modified. Please reinitialise card.")
        return None
    transact_list = transact_response.split(" ")
    string = b''
    hex_transact = []
    for each in transact_list:
        hex_transact.append(int(each, 16))
    string = b''
    for each in hex_transact:
        string += hex(each)[2:].encode('utf-8').upper()
    md5 = hashlib.md5(string).hexdigest().upper()
    saved_md5 = rollback_response.replace(" ", "")
    if md5 == saved_md5:
        print("MD5 value is identical. Data unlikely to be tampered or torn.")
    else:
        return None
    return 'valid'


def write_transaction_history(reader, action, value, station_action):
    cmd_transact = [0xFF, 0xD6, 0x00, 0x09, 0x10]
    cmd_roll_back = [0xFF, 0xD6, 0x00, 0x0A, 0x10]
    cmd_transact_content = []
    if action == 'tap in':
        cmd_transact_content.append(0x00)
    elif action == 'tap out':
        cmd_transact_content.append(0x01)

    hex_value = hex(value)
    pad_len = 10 - len(hex_value)
    if pad_len > 0:
        hex_value = hex_value[2:]
        new_value = pad_len * '0' + hex_value
    else:
        new_value = hex_value
    cmd_transact_content.append(int(new_value[0:2], 16))
    cmd_transact_content.append(int(new_value[2:4], 16))
    cmd_transact_content.append(int(new_value[4:6], 16))
    cmd_transact_content.append(int(new_value[6:8], 16))
    hex_station = int(hex(ord(station_action))[2:4], 16)
    cmd_transact_content.append(hex_station)
    date = dt.datetime.now(pytz.timezone('Asia/Singapore'))
    new_time = str(hex(calendar.timegm(date.timetuple())))
    cmd_transact_content.append(int(new_time[2:4], 16))
    cmd_transact_content.append(int(new_time[4:6], 16))
    cmd_transact_content.append(int(new_time[6:8], 16))
    cmd_transact_content.append(int(new_time[8:10], 16))
    totpvalue = totp('CPSSmartCard', int(hex(calendar.timegm(date.timetuple()))[2:], 16), 30, 6, 'sha1')
    totpvalue = hex(int(totpvalue))[2:]
    totp_pad_len = 6 - len(totpvalue)

    if totp_pad_len > 0:
        totpvalue = totp_pad_len * '0' + totpvalue
    cmd_transact_content.append(int(totpvalue[0:2], 16))
    cmd_transact_content.append(int(totpvalue[2:4], 16))
    cmd_transact_content.append(int(totpvalue[4:6], 16))
    cmd_transact_content.append(int('0', 16))
    cmd_transact_content.append(int('0', 16))
    cmd_transact_content.append(int('0', 16))

    string = b''
    for each in cmd_transact_content:
        string += hex(each)[2:].encode('utf-8').upper()
    md5 = hashlib.md5(string).hexdigest().upper()

    cmd_roll_back.append(int(md5[0:2], 16))
    cmd_roll_back.append(int(md5[2:4], 16))
    cmd_roll_back.append(int(md5[4:6], 16))
    cmd_roll_back.append(int(md5[6:8], 16))
    cmd_roll_back.append(int(md5[8:10], 16))
    cmd_roll_back.append(int(md5[10:12], 16))
    cmd_roll_back.append(int(md5[12:14], 16))
    cmd_roll_back.append(int(md5[14:16], 16))
    cmd_roll_back.append(int(md5[16:18], 16))
    cmd_roll_back.append(int(md5[18:20], 16))
    cmd_roll_back.append(int(md5[20:22], 16))
    cmd_roll_back.append(int(md5[22:24], 16))
    cmd_roll_back.append(int(md5[24:26], 16))
    cmd_roll_back.append(int(md5[26:28], 16))
    cmd_roll_back.append(int(md5[28:30], 16))
    cmd_roll_back.append(int(md5[30:32], 16))
    cmd_transact += cmd_transact_content
    connection = reader.createConnection()
    try:
        connection.connect()
        send_apdu(connection, CMD_LOAD_KEY)
        send_apdu(connection, CMD_AUTH_BLOCK_LAST_TRANSACTION)
        response, status_code = send_apdu(connection, cmd_transact)
        send_apdu(connection, CMD_AUTH_BLOCK_ROLL_BACK)
        send_apdu(connection, cmd_roll_back)

    except NoCardException:
        print("No smart card found.")
        return None
    except CardConnectionException:
        print("Card reader cannot be found, please check connection of card reader.")
        return None
    if status_code == "SW1: 90, SW2: 00":
        print("Value written to block 09 and 0A.")
    else:
        print("Failed to retrieve UID.")
        exit()
    return response


def get_transaction(reader):
    connection = reader.createConnection()
    try:
        connection.connect()
        send_apdu(connection, CMD_LOAD_KEY)
        send_apdu(connection, CMD_AUTH_BLOCK_LAST_TRANSACTION)
        transact_response, transact_status_code = send_apdu(connection, CMD_READ_TRANSACTION_LOG)
        send_apdu(connection, CMD_AUTH_BLOCK_ROLL_BACK)
        rollback_response, rollback_status_code = send_apdu(connection, CMD_READ_BLOCK_ROLL_BACK)

    except NoCardException:
        print("No smart card found.")
        return None
    except CardConnectionException:
        print("Card reader cannot be found, please check connection of card reader.")
        return None
    if transact_status_code == "SW1: 90, SW2: 00" and rollback_status_code == "SW1: 90, SW2: 00":
        print("Successful transaction.")
    else:
        print("Error retrieving transaction history and rollback value.")
        exit()
    # print(f"Transact: {transact_response}")
    # print(f"Rollback: {rollback_response}")
    if transact_response[0:2] == '00':
        action = 'tap in'
    elif transact_response[0:2] == '01':
        action = 'tap out'
    value = eval('0x' + transact_response[3:14].replace(" ", ""))
    station = bytes.fromhex(transact_response[15:17]).decode('utf-8')
    epoch_decimal = (int(transact_response[18:29].replace(" ", ""), 16))
    return action, value, station, epoch_decimal


def main():
    reader = init_reader()

    print("\nWelcome to the Override UI menu \nPlease Select your choice")
    while True:
        print("=" * 44)
        print("Choice 1: Initialize card as new.")
        print("Choice 2: Top-up card (any value)")
        print("Choice 3: Check Balance")
        print("Choice 4: Tap-in self-defined Station")
        print("Choice 5: Tap-out self-defined Station")
        print("Choice 6: View last debit/refund transaction")
        print("Choice 7: Exit \n")
        user_choice = input("Enter your choice: ")
        print("")
        match user_choice:
            case '1':
                initialise(reader)
            case '2':
                max_value_for_top = max_top_up_value(reader)
                value = get_topup_input(max_value_for_top)
                if value:
                    top_up(reader, value)
            case '3':
                check_balance(reader)
            case '4':
                tap_in_station = get_station_input()
                if tap_in_station:
                    charge_fare = get_max_tap_in_fare_value(tap_in_station)
                    balance = process_value(check_balance(reader))
                    print(f'Card fare is: ${charge_fare / 100:.2f}')
                    if balance < (charge_fare / 100):
                        print(
                            f"Your card balance is insufficient to start a journey on this station. Please top up ${((charge_fare / 100) - balance):.2f}.")
                    else:
                        verified_status = verify_transaction_history(reader)
                        if verified_status == 'empty':
                            debit(reader, charge_fare)
                            write_transaction_history(reader, 'tap in', charge_fare, tap_in_station)
                        elif verified_status == 'valid':
                            transaction_action, transaction_fare, transaction_station, epoch_decimal = get_transaction(
                                reader)
                            if transaction_action == 'tap out':
                                print("Double debit detected, last full fare charged, continuing transaction.")
                                debit(reader, charge_fare)
                                write_transaction_history(reader, 'tap in', charge_fare, tap_in_station)
                            if transaction_action == 'tap in':
                                debit(reader, charge_fare)
                                write_transaction_history(reader, 'tap in', charge_fare, tap_in_station)
                        else:
                            print("Card tampering or tearing detected. Please reinitialize card.")
                else:
                    print("Invalid station name provided.")
            case '5':
                tap_out_station = get_station_input()
                if tap_out_station:
                    balance = process_value(check_balance(reader))
                    verified_status = verify_transaction_history(reader)
                    if verified_status == 'empty':
                        print("No record found charging maximum possible fare if possible.")
                        max_possible_fare = get_max_tap_in_fare_value(tap_out_station) / 100
                        if balance > max_possible_fare:
                            debit(reader, int(max_possible_fare) * 100)
                            print("Logging as 0 credit for tap out.")
                            write_transaction_history(reader, 'tap out', 0, tap_out_station)
                        else:
                            print("Please proceed to counter for assistance.")
                    if verified_status == 'valid':
                        transaction_action, transaction_fare, transaction_station, epoch_decimal = get_transaction(
                            reader)
                        if transaction_action == 'tap out':
                            print("Tap in not found, charging maximum possible fare if possible.")
                            max_possible_fare = get_max_tap_in_fare_value(tap_out_station) / 100
                            if balance > max_possible_fare:
                                debit(reader, int(max_possible_fare) * 100)
                                print("Logging as 0 credit for tap out.")
                                write_transaction_history(reader, 'tap out', 0, tap_out_station)
                            else:
                                print("Please proceed to counter for assistance.")
                        if transaction_action == 'tap in':
                            print("Tap in found, refunding unused fare.")
                            fare_used = find_used_fare(transaction_station, tap_out_station)
                            refund_val = tap_out_fare_refund_value(transaction_station, tap_out_station)
                            print(f"Actual fare cost: ${fare_used / 100:.2f}. Refund value: ${refund_val / 100:.2f}")
                            if refund_val > (4294967295 - balance):
                                print("Card value is maxed. Unable to credit refund.")
                            else:
                                top_up(reader, int(refund_val))
                                write_transaction_history(reader, 'tap out', int(refund_val), tap_out_station)
                else:
                    print("Invalid station name provided.")
            case '6':
                verified_status = verify_transaction_history(reader)
                if verified_status == 'empty':
                    pass
                elif verified_status == 'valid':
                    transaction_action, transaction_fare, transaction_station, epoch_decimal = get_transaction(
                        reader)
                    print(
                        f"The last transaction was a {transaction_action} of ${transaction_fare / 100:.2f} at station {transaction_station} around {GMT_8.localize(dt.datetime.fromtimestamp(epoch_decimal))}.")
            case '7':
                print("Thank you for using CPS Smart Card!")
                break
            case _:
                print("Invalid Input, please try again.")


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

# Argparse logic
reader = init_reader()
if args.new:
    initialise(reader)
if args.topup:
    top_up_value = get_topup_textfile_value()
    max_value_for_top = max_top_up_value(reader)
    if max_value_for_top < top_up_value:
        top_up(reader, top_up_value)
    else:
        print(f"Unable to top up amount. Value exceeds limit. You may only top you {max_value_for_top}.")
if args.balance:
    check_balance(reader)
if args.tap_in:
    station = get_station_letter_textfile_value()
    fare = MAX_FARE_LOOKUP[station]

if args.tap_out:
    station = get_station_letter_textfile_value()

if args.CLI:
    main()

# get_transaction(reader)
