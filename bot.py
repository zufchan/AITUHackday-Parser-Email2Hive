import json
import sys
from termcolor import colored
from thehive4py.api import TheHiveApi
from thehive4py.models import *
from thehive4py.query import *
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.multipart import *
import smtplib
import configparser
import telebot
from telebot import types


try:
    config = configparser.ConfigParser()
    config.read('config.conf')
except Exception as e:
    print(e)
    sys.exit()

BOT_URL = config['hackday parser']['BOT_TELEGRAM']
bot = telebot.TeleBot(BOT_URL)
THEHIVE_URL = config['hackday parser']['THEHIVE_URL']
THEHIVE_API_KEY = config['hackday parser']['THEHIVE_API_KEY']
api = TheHiveApi(THEHIVE_URL, THEHIVE_API_KEY)

class User:
    severity = None
    email = None

def send_mail(subject, content, email):
    login = config['hackday parser']['email_username']
    password = config['hackday parser']['email_password']
    url = "smtp.yandex.kz"
    toaddr = email
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = config['hackday parser']['email_username']
    body = content
    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP_SSL(url, 465)
    except TimeoutError:
        print(colored('Timeout error', 'red'))
    try:
        server.login(login, password)
        server.sendmail(login, toaddr, msg.as_string())
        print("Message sent")
    except Exception as e:
        print(e)

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    markup = types.ReplyKeyboardMarkup(row_width=4, resize_keyboard=True)
    itembtn1 = types.KeyboardButton('Low')
    itembtn2 = types.KeyboardButton('Medium')
    itembtn3 = types.KeyboardButton('High')
    itembtn4 = types.KeyboardButton('All')
    markup.add(itembtn1, itembtn2, itembtn3, itembtn4)
    msg = bot.send_message(message.chat.id, "Hello, select what type of vulnerabilities you want to receive", reply_markup=markup)
    bot.register_next_step_handler(msg, email)

def email(message):
    User.severity = message.text
    msg = bot.send_message(message.chat.id, "Enter your email for receive the High level vulnerabilities:", reply_markup=telebot.types.ReplyKeyboardRemove())
    bot.register_next_step_handler(msg, send)

def send(message):
    User.email = message.text
    id = 1
    i = 1
    while True:
        if User.severity == "Low":
            try:
                query = Eq('severity', Severity.LOW.value)
                response = api.find_alerts(query=query)
                j = json.dumps(response.json(), indent=4, sort_keys=True)
                d = json.loads(j)
                if id != d[-1]['id']:
                    id = d[-1]['id']
                    bot.send_message(message.chat.id,
                                     "TheHive ID: %s\nTitle: %s\nSeverity: Low" % (d[-1]['id'], d[-1]['title']))
            except Exception as e:
                print("Send the severity error: %s"%e)
        elif User.severity == "Medium":
            try:
                query = Eq('severity', Severity.MEDIUM.value)

                response = api.find_alerts(query=query)
                j = json.dumps(response.json(), indent=4, sort_keys=True)
                d = json.loads(j)
                if id != d[-1]['id']:
                    id = d[-1]['id']
                    bot.send_message(message.chat.id,
                                     "TheHive ID: %s\nTitle: %s\nSeverity: Medium" % (d[-1]['id'], d[-1]['title']))
            except Exception as e:
                print("Send the severity error: %s"%e)
        elif User.severity == "High":
            try:
                query = Eq('severity', Severity.HIGH.value)
                response = api.find_alerts(query=query)
                j = json.dumps(response.json(), indent=4, sort_keys=True)
                d = json.loads(j)
                if id != d[-1]['id']:
                    id = d[-1]['id']
                    bot.send_message(message.chat.id,
                                     "TheHive ID: %s\nTitle: %s\nSeverity: High" % (d[-1]['id'], d[-1]['title']))
            except Exception as e:
                print("Send the severity error: %s"%e)
        elif User.severity == "All":
            try:
                response = api.find_alerts()
                j = json.dumps(response.json(), indent=4, sort_keys=True)
                d = json.loads(j)
                if id != d[-1]['id']:
                    id = d[-1]['id']
                    bot.send_message(message.chat.id,
                                    "TheHive ID: %s\nTitle: %s\nSeverity: %d" % (d[-1]['id'], d[-1]['title'], d[-1]['severity']), reply_markup=telebot.types.ReplyKeyboardRemove())
            except Exception as e:
                print("Send the severity error: %s"%e)
        try:
            query = Eq('severity', Severity.HIGH.value)
            response = api.find_alerts(query=query)
            j = json.dumps(response.json(), indent=4, sort_keys=True)
            d = json.loads(j)
            if i != d[-1]['id']:
                i = d[-1]['id']
                body = "TheHive ID: %s\nTitle: %s\nSeverity: %d" % (d[-1]['id'], d[-1]['title'], d[-1]['severity'])
                send_mail(d[-1]['title'], body, User.email)
        except Exception as e:
            print("Send the email error: %s" % e)


if __name__ == '__main__':
    bot.polling(none_stop=True)

