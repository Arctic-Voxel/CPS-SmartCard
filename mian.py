from smartcard.System import readers
from smartcard.util import toHexString

# MIFARE Ultralight commands
CMD_GET_UID = [0x00, 0x00, 0x00, 0x00, 0x00]

CMD_GET_PURSE_FILE = [0x90, 0x32, 0x03, 0x00, 0x00]

CMD_GET_TRANSACTION_LOG = [0x90, 0x32, 0x03, 0x00, 0x01, 0x00, 0x00]


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


if __name__ == "__main__":
    main()