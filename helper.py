def fistCharToUpper(message, decode = 0):
    if(decode!=1):
        message = message.decode('utf-8')
    
    formatted_message = message[0].upper() + message[1:]
    result = formatted_message.encode('utf-8')
    return result

def fistCharToUpperClient(message):
    formatted_message = message[0].upper() + message[1:]
    result = formatted_message
    return result
    