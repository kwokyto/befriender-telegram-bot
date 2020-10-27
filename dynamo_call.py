## THIS IS THE BEFRIENDER DYNAMO_CALL

import os
import logging
import boto3
import botocore
import hashlib
import random
from boto3.dynamodb.conditions import Attr

# Logging is cool!
logger = logging.getLogger()
if logger.handlers:
    for handler in logger.handlers:
        logger.removeHandler(handler)
logging.basicConfig(level=logging.INFO)

# Setting up client with AWS
client = boto3.resource("dynamodb")
TableName = "BefrienderTable"
table = client.Table(TableName)

def is_registered(chat_id):
    # check if chat_id exists in dynamo
    logger.info(str(chat_id) + " entered is_registered")
    hasher = hashlib.sha256()
    string_to_hash = str(chat_id)
    hasher.update(string_to_hash.encode('utf-8'))
    hashid = hasher.hexdigest()
    try:
        response = table.get_item(
            Key = {
                "hashid": hashid})
        item = response["Item"]
        logger.info("User item found, user is registered")
        return True
    except Exception as e:
        logger.info("ERROR --> " + str(e))
        logger.info("User item not found, user not yet registered")
        return False # COMPLETED AND WORKS

def check_password(matric_number, hash):
    string_to_hash = matric_number + "loveusp"
    password = hashlib.md5(string_to_hash.encode()).hexdigest()
    return hash == password # COMPLETED AND WORKS

def add_id(chat_id, matric_number):
    # add chat_id to dynamo
    # if successful, return true, else return false
    logger.info(str(chat_id) + " entered add_id")

    username_list = ["alligator", "alpaca", "ant", "anteater", "antelope", "armadillo", "axolotl", "baboon", "badger", "barracuda", \
                     "bat", "bear", "beaver", "beetle", "bird", "bison", "boar", "buffalo", "bulbul", "butterfly", \
                     "camel", "capybara", "cat", "chameleon", "cheetah", "chicken", "chimpanzee", "chipmunk", "cobra", "cockatoo", \
                     "cow", "coyote", "crab", "crane", "crocodile", "crow", "deer", "dingo", "dog", "dolphin", \
                     "dove", "dragon", "dragonfly", "duck", "eagle", "egret", "elephant", "elk", "emu", "falcon", \
                     "ferret", "flamingo", "fox", "frog", "gazelle", "gecko", "gerbil", "goat", "goose", "gorilla", \
                     "groundhog", "gull", "hawk", "hedgehog", "hen", "heron", "hippoopotamus", "hornbill", "hyena", "ibis", \
                     "iguana", "jackal", "jaguar", "kangaroo", "koala", "komodo", "kookaburra", "lemur", "leopard", "lion", \
                     "lizard", "llama", "manatee", "meerkat", "mongoose", "monkey", "moose", "nighthawk", "ocelot", "orca", \
                     "ostrich", "otter", "owl", "ox", "parrot", "peacock", "pelican", "penguin", "pigeon", "platypus", \
                     "porcupine", "possum", "prayingmantis", "puffin", "pygmy", "python", "quail", "rabbit", "raccoon", "rat", \
                     "rattlesnake", "raven", "reindeer", "rhino", "roadrunner", "robin", "salmon", "seal", "shark", "sheep", \
                     "skunk", "sloth", "sparrow", "spider", "squirrel", "starfish", "stork", "swan", "tarantula", \
                     "tiger", "tortoise", "toucan", "turkey", "turtle", "viper", "vulture", "wallaby", "whale", "wolf", \
                     "wombat", "woodpecker", "yak", "zebra"]
    
    username = "usp" + username_list[random.randint(0,143)]
    partner_id = 0
    blacklist = 0
    hasher = hashlib.sha256()
    string_to_hash = str(chat_id)
    hasher.update(string_to_hash.encode('utf-8'))
    hashid = hasher.hexdigest()

    try: 
        # Stores data in table  if it exists in dynamodb
        response = table.update_item(
        Key = {"hashid": hashid},
        UpdateExpression = "SET {} = :val1, {} =:val2, {} = :val3, {} = :val4, {} = :val5, {} = :val6".format(\
                "chat_id", "matric_number", "username", "partner_id", "blacklist", "last_partner"),
        ExpressionAttributeValues = {":val1": chat_id, ":val2": matric_number, ":val3": username, \
                                     ":val4": partner_id, ":val5": blacklist, ":val6":partner_id})
        logger.info("New user successfully added into dynamodb")
        return True
    except botocore.exceptions.ClientError as e:
        # Creates table if it doesn't exist in dynamodb
        if e.response["Error"]["Message"] == "Requested resource not found":
                logger.info("Table does not exist, creating table in dynamodb...")
                createtable = client.create_table(
                        TableName = TableName,
                        KeySchema = [
                                {
                                        "AttributeName": 'hashid',
                                        "KeyType": "HASH"
                                        }
                                ],
                        AttributeDefinitions = [
                                {
                                        "AttributeName": "hashid",
                                        "AttributeType": "S"
                                        }
                                ],
                        ProvisionedThroughput = {
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
                })
                logger.info("Table created, values saved in dynamodb")
        logger.info("ERROR: new user NOT added into dynamodb --> " + str(e))
        return False # COMPLETED AND WORKS

def get_username(chat_id):
    # get username from chat id
    logger.info(str(chat_id) + " entered get_username")

    hasher = hashlib.sha256()
    string_to_hash = str(chat_id)
    hasher.update(string_to_hash.encode('utf-8'))
    hashid = hasher.hexdigest()
    try:
        response = table.get_item(
            Key = {
                "hashid": hashid})
        item = response["Item"]
        logger.info("User item found, username returned")
        return item["username"]
    except Exception as e:
        logger.info("ERROR User item not found--> " + str(e))
        return False # COMPLETED AND WORKS

def get_partner_id(chat_id):
    # get partner_id
    logger.info(str(chat_id) + " entered get_partner_id")

    hasher = hashlib.sha256()
    string_to_hash = str(chat_id)
    hasher.update(string_to_hash.encode('utf-8'))
    hashid = hasher.hexdigest()
    try:
        response = table.get_item(
            Key = {
                "hashid": hashid})
        item = response["Item"]
        logger.info("User item found, returning " + str(item["partner_id"]))
        return item["partner_id"]
    except Exception as e:
        logger.info("ERROR User item not found--> " + str(e))
        return False # COMPLETED AND WORKS

def match(chat_id):
    # tries to match this with someone
    # if successful, return partner_id, else return false
    logger.info(str(chat_id) + " entered match")

    # if user already has a partner, return partner_id
    partner_id = get_partner_id(chat_id)
    if partner_id != 0 and partner_id != 1 and partner_id != False:
        return partner_id

    hasher = hashlib.sha256()
    string_to_hash = str(chat_id)
    hasher.update(string_to_hash.encode('utf-8'))
    chat_id_hashed = hasher.hexdigest()
    response = table.get_item(
        Key = {
            "hashid": chat_id_hashed})
    item = response["Item"]
    logger.info("User item found, last_partner found")
    last_partner = item["last_partner"]

    response = table.scan(
        FilterExpression = ~Attr("chat_id").eq(chat_id) & Attr("partner_id").eq(1) & Attr("blacklist").eq(0) & ~Attr("chat_id").eq(last_partner)
    )
    items = response["Items"]
    logger.info("Items is: " + str(items))

    if len(items) == 0:
        logger.info("No available users to match with.")
        table.update_item(
            Key = {
                "hashid": chat_id_hashed},
            UpdateExpression= "SET partner_id = :val1",
            ExpressionAttributeValues = {":val1": 1})
        logger.info("Self's partner_id set to 1, returning False.")
        return False

    partner_id = items[0]["chat_id"]
    hasher = hashlib.sha256()
    string_to_hash = str(chat_id)
    hasher.update(string_to_hash.encode('utf-8'))
    chat_id_hashed = hasher.hexdigest()
    table.update_item(
        Key = {
            "hashid": chat_id_hashed},
        UpdateExpression= "SET partner_id = :val1, last_partner = :val2",
        ExpressionAttributeValues = {":val1": partner_id, ":val2": partner_id})
    logger.info("Self's partner_id updated to partner_id.")
        
    hasher = hashlib.sha256()
    string_to_hash = str(partner_id)
    hasher.update(string_to_hash.encode('utf-8'))
    partner_id_hashed = hasher.hexdigest()
    table.update_item(
        Key = {
            "hashid": partner_id_hashed},
        UpdateExpression= "SET partner_id = :val1, last_partner = :val2",
        ExpressionAttributeValues = {":val1": chat_id, ":val2": chat_id})
    logger.info("Partner's partner_id updated to own chat_id.")

    logger.info("Returning partner_id = " + str(partner_id))
    return partner_id # COMPLETED AND WORKS 

def unmatch(chat_id):
    # unmatch user and partner
    # if successful, return old partner_id, else false
    logger.info(str(chat_id) + " entered unmatch")

    hasher = hashlib.sha256()
    string_to_hash = str(chat_id)
    hasher.update(string_to_hash.encode('utf-8'))
    chat_id_hashed = hasher.hexdigest()
    response = table.get_item(
        Key = {
            "hashid": chat_id_hashed})
    partner_id = response["Item"]["partner_id"]

    if partner_id == 0 or partner_id == 1:
        logger.info("User is not yet matched, returning False.")
        return False

    hasher = hashlib.sha256()
    string_to_hash = str(partner_id)
    hasher.update(string_to_hash.encode('utf-8'))
    partner_id_hashed = hasher.hexdigest()
    table.update_item(
        Key = {
            "hashid": partner_id_hashed},
        UpdateExpression= "SET partner_id = :val1",
        ExpressionAttributeValues = {":val1": 0})
    logger.info("Partner's item updated to 0.")
    
    table.update_item(
        Key = {
            "hashid": chat_id_hashed},
        UpdateExpression= "SET partner_id = :val1",
        ExpressionAttributeValues = {":val1": 0})
    logger.info("Self item updated to 0.")

    return partner_id # COMPLETED AND WORKS

def report(chat_id):
    # blacklist partner, return False if no partner
    logger.info(str(chat_id) + " entered report")

    hasher = hashlib.sha256()
    string_to_hash = str(chat_id)
    hasher.update(string_to_hash.encode('utf-8'))
    chat_id_hashed = hasher.hexdigest()
    response = table.get_item(
        Key = {
            "hashid": chat_id_hashed})
    partner_id = response["Item"]["partner_id"]

    if partner_id == 0 or partner_id == 1:
        logger.info("User is not yet matched.")
        return False

    hasher = hashlib.sha256()
    string_to_hash = str(partner_id)
    hasher.update(string_to_hash.encode('utf-8'))
    partner_id_hashed = hasher.hexdigest()
    table.update_item(
        Key = {
            "hashid": partner_id_hashed},
        UpdateExpression= "SET blacklist = :val1",
        ExpressionAttributeValues = {":val1": 1})
    logger.info("Partner is blacklisted.")

    return True # COMPLETED AND WORKS

def is_blacklisted(chat_id):
    # return true if blacklisted, false otherwise
    # return true if there is an error
    logger.info(str(chat_id) + " entered is_blacklisted")

    hasher = hashlib.sha256()
    string_to_hash = str(chat_id)
    hasher.update(string_to_hash.encode('utf-8'))
    hashid = hasher.hexdigest()

    try:
        response = table.get_item(
            Key = {
                "hashid": hashid})
        item = response["Item"]
        logger.info("User item found, blacklist status returned")
        return item["blacklist"] == 1 and (item["partner_id"] == 0 or item['partner_id'] == 1)
    except Exception as e:
        logger.info("ERROR User item not found--> " + str(e))
        return True # COMPLETED AND WORKS

def delete_user(matric_number, password):
    # delete user entry using NUSNET ID
    if password != "IAMTHELOVEUSPADMIN":
        return False

    response = table.scan(
        FilterExpression = Attr("matric_number").eq(matric_number)
    )
    items = response["Items"]

    logger.info("Items is: " + str(items))

    if len(items) == 0:
        logger.info("Matric number not found.")
        return False

    hashid = items[0]["hashid"]

    try:
        table.delete_item(
            Key = {"hashid": hashid}
        )
        logger.info("User item deleted")
        return True
    except Exception as e:
        logger.info("ERROR --> " + str(e))
        logger.info("User item not deleted")
        return False # COMPLETED AND WORKS

def debugging_mode(chat_id, text):
    ADMIN_ID = 197107238 # change to current tester chat_id
    debug_message = "The bot is currently under maintenance. We will inform you when the bot is back up. Thank you for your patience."
    template = {"message": "", "receiver_id": ""}
    responses_list = []

    if chat_id != ADMIN_ID: # if someone send message during debugging
        template["message"] = debug_message
        template["receiver_id"] = chat_id
        responses_list.append(template)
        return responses_list

    if text == "/broadcast_debug": # inform everyone that debugging has started
        response = table.scan(
            FilterExpression = ~ Attr("username").eq("")
        )
        items = response["Items"]
        logger.info("Items is: " + str(items))

        template["message"] = "uspadmin:\n" + debug_message
        for user in items:
            response = template.copy()
            response["receiver_id"] = str(user["chat_id"])
            responses_list.append(response)
        logger.info("Broadcast message sent")
        return responses_list

    return True # allow only tester to continue testing code

def all_ok(password):
    if password != "IAMTHELOVEUSPADMIN":
        return False

    all_ok_message = "uspadmin:\nThe bot is back in business! Thank you for your patience."
    template = {"message": all_ok_message, "receiver_id": ""}
    responses_list = []

    response = table.scan(
        FilterExpression = ~ Attr("username").eq("")
    )
    items = response["Items"]
    logger.info("Items is: " + str(items))

    for user in items:
        response = template.copy()
        response["receiver_id"] = str(user["chat_id"])
        responses_list.append(response)
    logger.info("Broadcast message sent")
    return responses_list