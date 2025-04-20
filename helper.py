from datetime import datetime
import logging

def setup_logging():
    logging.basicConfig(
        filename="server.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

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

def get_current_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")