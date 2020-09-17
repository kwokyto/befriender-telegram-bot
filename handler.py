## THIS IS BEFRIENDER HANDLER

import json
import telegram
import os
import logging

from dynamo_call import *

# Logging is cool!
logger = logging.getLogger()
if logger.handlers:
    for handler in logger.handlers:
        logger.removeHandler(handler)
logging.basicConfig(level=logging.INFO)

OK_RESPONSE = {
    'statusCode': 200,
    'headers': {'Content-Type': 'application/json'},
    'body': json.dumps('ok')
}
ERROR_RESPONSE = {
    'statusCode': 400,
    'body': json.dumps('Oops, something went wrong!')
}


def configure_telegram():
    """
    Configures the bot with a Telegram Token.

    Returns a bot instance.
    """

    TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN')
    if not TELEGRAM_TOKEN:
        logger.error('The TELEGRAM_TOKEN must be set')
        raise NotImplementedError

    return telegram.Bot(TELEGRAM_TOKEN)

def webhook(event, context):
    """
    Runs the Telegram webhook.
    """

    bot = configure_telegram()
    logger.info('Event: {}'.format(event))

    if event.get('httpMethod') == 'POST' and event.get('body'): 
        logger.info('Message received')
        update = telegram.Update.de_json(json.loads(event.get('body')), bot)

        try:
            chat_id = update.message.chat.id
            text = update.message.text
        except:
            chat_id = update.edited_message.chat.id
            text = update.edited_message.text

        #bot.sendMessage(chat_id=chat_id, text="Bot upgrade in progess...")

        lst = get_response(text, chat_id)
        for dic in lst:
            chat_id = dic["receiver_id"]
            text = dic["message"]
            bot.sendMessage(chat_id=chat_id, text=text)
        logger.info('Message sent')

        return OK_RESPONSE

    return ERROR_RESPONSE

def set_webhook(event, context):
    """
    Sets the Telegram bot webhook.
    """

    logger.info('Event: {}'.format(event))
    bot = configure_telegram()
    url = 'https://{}/{}/'.format(
        event.get('headers').get('Host'),
        event.get('requestContext').get('stage'),
    )
    webhook = bot.set_webhook(url)

    if webhook:
        return OK_RESPONSE

    return ERROR_RESPONSE

def get_response(text, chat_id):
    """
    Process a message from Telegram
    """

    # Command Responses
    unregistered_message = \
        "You are not yet registered, please contact Love, USP for further details."
    already_registered_message = \
        "You are already registered!"
    to_register_message = \
        "To register, please use the following format.\n/register <matric number> <password>\n./register AxxxxxxxA pAssw0rdH3r3"
    registration_success_message = \
        "Registration success! Your username is "
    registration_failed_message = \
        "Registration failed, please try again or contact Love, USP."
    wrong_password_message = \
        "Wrong password! Please try again."
    start_message = \
        "Welcome to Love, USP Befriender chat! Enter /register to register."
    match_fail_message = \
        "We are trying to find you a friend. We will inform you when there is someone available."
    match_success_message = \
        "Yay! We have found you a friend. Go ahead and say hi! Your friend's username is "
    unmatch_success_message = \
        "You have been unfriended :( Enter /befriend to start another conversation"
    unmatch_fail_message = \
        "Unfriend failed. Please try again."
    no_partner_message = \
        "You currently are not friended with anyone. Enter /befriend to start conversation"
    alrd_got_partner_error_message = \
        "You already have a friend."
    no_partner_error_message = \
        "You do not have a friend yet."
    report_message = \
        "Report success. Please contact Love, USP."
    blacklisted_message = \
        "You have been blacklisted, please contact Love, USP."
    invalid_command_message = \
        "Invalid command."
    non_text_message = \
        "Non-text detected. Sorry, we still do not support non-text messages."

    # Setting main objects
    first_response = {"message": unregistered_message, "receiver_id": chat_id}
    second_response = {"message": "", "receiver_id": ""}
    responses_list = [first_response] # to be returned

    ## FOR TESTING ONLY
    #matric_number = text[10:19]
    #hash = text[20:]
    #if not check_password(matric_number, hash):
    #    first_response["message"] = wrong_password_message
    #    return responses_list
    #first_response["message"] = add_id(chat_id, matric_number)
    #return responses_list
    
    
    # Validity checking
    if text == None:
        first_response["message"] = non_text_message
        return responses_list # COMPLETED AND WORKS

    # Command Handlers
    if text == "/start":
        first_response["message"] = start_message
        return responses_list # COMPLETED AND WORKS

    if text[:9] == "/register":
        # check if user is already registered
        if is_registered(chat_id):
            first_response["message"] = already_registered_message
            return responses_list
        
        # if user just puts /register
        if text == "/register":
            first_response["message"] = to_register_message
            return responses_list

        # if user is not registered
        matric_number = text[10:19]
        hash = text[20:]

        # if password is wrong
        # use https://www.md5hashgenerator.com/
        if not check_password(matric_number, hash):
            first_response["message"] = wrong_password_message
            return responses_list

        #if password is correct
        if add_id(chat_id, matric_number):
            first_response["message"] = registration_success_message + get_username(chat_id) + "."
        else:
            first_response["message"] = registration_failed_message
        return responses_list # COMPLETED AND WORKS
    
    # if user is not registered, do NOT continue
    # check if user is already registered
    if not is_registered(chat_id):
        first_response["message"] = unregistered_message
        return responses_list # COMPLETED AND WORKS

    if text == "/username":
        first_response["message"] = "Your username is: " + get_username(chat_id)
        return responses_list # COMPLETED AND WORKS

    if is_blacklisted(chat_id):
        first_response["message"] = blacklisted_message
        return responses_list # COMPLETED AND WORKS
    
    if text == "/befriend":
        partner_id = match(chat_id)
        if not partner_id:
            first_response["message"] = match_fail_message
            return responses_list
        first_response["message"] = match_success_message + get_username(partner_id) + "."
        second_response["message"] = match_success_message + get_username(chat_id) + "."
        second_response["receiver_id"] = str(partner_id)
        responses_list.append(second_response)
        return responses_list # COMPLETED AND WORKS

    if text == "/unfriend":
        partner_id = unmatch(chat_id)
        if partner_id == False:
           first_response["message"] = no_partner_error_message
           return responses_list
        if not partner_id:
           first_response["message"] = unmatch_fail_message
           return responses_list
        first_response["message"] = unmatch_success_message
        second_response["message"] = unmatch_success_message
        second_response["receiver_id"] = str(partner_id)
        responses_list.append(second_response)
        return responses_list # COMPLETED AND WORKS

    if text == "/report":
        partner_id = report(chat_id)
        if not partner_id:
           first_response["message"] = no_partner_error_message
           return responses_list
        first_response["message"] = report_message
        return responses_list # COMPLETED AND WORKS

    if text[:7] == "/delete":
        matric_number = text[8:17]
        password = text[18:]
        if delete_user(matric_number, password):
            first_response["message"] = "User deleted successfully."
        else:
            first_response["message"] = "Deletion failed."
        return responses_list # COMPLETED AND WORKS

    if text[0] == "/":
        first_response["message"] = invalid_command_message
        return responses_list # COMPLETED AND WORKS

    partner_id = get_partner_id(chat_id)
    if partner_id and partner_id != 1:
        first_response["receiver_id"] = str(partner_id)
        username = get_username(chat_id)
        first_response["message"] = username + ":\n" + text
        return responses_list # COMPLETED AND WORKS

    first_response["message"] = no_partner_message
    return responses_list # COMPLETED AND WORKS