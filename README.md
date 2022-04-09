# AITUHackday-Parser-Email2Hive
Code for AITUHackDay: Creative Industry Hackathon case for KazDream, by Unknown Impact team

# Purpose
The script parser.py reads an email and creates an alert instance to [TheHive](https://thehive-project.org/) platform.

# Configuration
You can configure the following through the config.conf:
- Email username (From which we parse logs)
- Email password 
- Email folder (The folder from which we will get emails; default: INBOX)
- IMAP domain (The IMAP domain of the email service. ex: imap.yandex.kz)
- TheHive url (url of the platform to which we pump alerts)
- TheHive API key (User's API key which we need to use for uploading alerts)
- Whitelist (A list of emails from which we will accept alerts)
- Telegram bot token (Bots token that we need to setup bot for notifications)

# Usage
## Parser
To start the script first you need thehive4py package installed on python3, then type following in the cli

```
nohup python3 parser.py &
```
You'll get a PID in the output, save it. If you want to stop the parser type following:

```
kill [PID]
```

## Send logs
Use this script for testing the perfomance of the parse bot

## Bot
Telegram bot for notifications on the alerts, you can filter the alerts by the severity.
