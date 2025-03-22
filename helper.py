def fistCharToUpper(message):
    decoded_message = message.decode('utf-8')
    formatted_message = decoded_message[0].upper() + decoded_message[1:]
    result = formatted_message.encode('utf-8')
    return result