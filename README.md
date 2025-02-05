# Befriender by Love, USP

![befriender logo](befriender_profile_pic.jpg)

Befriender was created based on loneliness in university, especially for freshman during the COVID19 pandemic. Since students, especially introverted ones find extreme difficulty to bond and form deep friendships through mass gatherings on Zoom, this idea was created to allow students to communicate through Telegram with new people in USP. This bot serves as a safe space for USP students to anonymously meet new friends on a private chat. In addition, with mental health as the primary focus of Love, USP, this bot serves as an avenue for students to share their struggles in school and life on a personal and secret basis.

The telegram bot can be accessed [here](https://telegram.me/anonchatbetabot).

:warning: This bot was disabled as of 17 April 2021. Contact @kwokyto on Telegram for any enquiries.

## Features

Through Befriender, you can befriend a fellow USP student and hold a private conversation with him/her.
All information will not be shared, other than a randomised username that would be assigned to each user upon registration.
While most would unfriend to end the conversation, students may personally exchange contact to continue their conversations on other platforms.
After unfriending, the student can then proceed to friend another student.
Students can also make a report if they feel harassed at any point in time.
Information will be taken to the admin for further actions.

## General Commands

Below are a list of available commands for users that can be used in the Befriender Telegram bot.

### `/start`

Returns a general welcome message.

### `/about`

Returns a bot description, along with the sign up link, FAQ link, and admins’ Telegram handles.

### `/register <NUSNET ID> <password>`

Registers the student into the Befriender system.
Non-registered students will not be able to use the features of the bot.
The password is specific to each student, and will be provided by Love, USP admin.

### `/username`

Shows the student's username.

### `/befriend`

Befriends student with another available student.
Users will not be re-paired with their most recent friend.
Upon successful befriending, both users will be notified and informed of each others username.

### `/unfriend`

Ends the current conversation.
After unpairing, users will not befriend another student unless the `/befriend` command called again.
Users will not be re-paired with their most recent friend.
Upon successful unfriending, both users will be notified.

### `/report`

Blacklists the user's current conversational partner.
User will be notified if the reporting is successful and asked to contact the Love, USP admin.
The partner being reported will NOT be informed.
The existing conversation will NOT ended until the `/unfriend` command is called.
Afterwards, blacklisted users will no longer be able to use any of the bot's features.

## Admin Commands

These commands should only be made known to the admin to prevent misuse.

### `/delete <NUSNET ID> <password>`

Unregisters the user with a certain NUSNET ID.
This is to ensure that admins can easily remove any user that may be causing distress in the chat.
The password used here is different from the password used in /register, and should only be known by the admin.

## Debugging

The following outlines the procedure for debugging.

1. In dynamo_call.py, insert admin chat ID in debugging_mode() function.
2. In handler.py, uncomment line to enable debugging mode.
3. Open command line and `serverless deploy`.
4. From now on, non-admins who send messages to the bot will receive an "under maintenance" message.
5. Only admin can use `/broadcast_debug`, to send an "under maintenance" message to all users.
6. Admin can continue testing the bot as a normal user while under debug mode.
7. To flush the message queue, set `flush = True` in handler.py and `serverless deploy`.
8. After debugging, comment line in handler.py for disable debugging mode.
9. In Telegram, send `/allok <password>` to send an "all ok" message to all users.

## FAQs

The FAQ for the bot can be found [here](https://www.tinyurl.com/loveuspbotfaq "Love USP Bot FAQs")

## AWS and Serverless Deployment

### Installing

```lang-none
# Open the command window in the bot file location

# Install the Serverless Framework
$ npm install serverless -g

# Install the necessary plugins
$ npm install
```

### Deploying

```lang-none
# Update AWS CLI in .aws/credentials

# Deploy it!
$ serverless deploy

# With the URL returned in the output, configure the Webhook
$ curl -X POST https://<your_url>.amazonaws.com/dev/set_webhook
```

### AWS Configurations

1. From the AWS Console, select AWS Lambda.
2. In AWS Lambda, select "befriender-bot-dev-webhook".
3. Select "Permissions" and select the Lambda role under "Execution role"
4. In AWS IAM, select "Attach policies" under "Permissions" and "Permissions policies"
5. Search for and select "AmazonDynamoDBFullAccess" and "Attach policy"
6. Run the Telegram bot with `/start` and register with `/register`
7. The first attempt at registration should return an error.
8. From the AWS Console, select AWS DynamoDB.
9. Under "Tables", ensure that the "BefrienderTable" table has been created.
10. Re-register with `/register`, and registration should be successful.

## Future Developments

- Improved welcome message to assist the registration process and what to expect and do next
