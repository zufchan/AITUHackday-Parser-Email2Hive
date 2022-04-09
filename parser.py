import time
import uuid
import imaplib
import re
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper
from thehive4py.exceptions import AlertException
import email
import configparser
import logging as log
import sys 

def email_listener(imap):
    result, data = imap.search(None, 'NEW')
    mail_ids = []
    for block in data:
        mail_ids += block.split()

    contents = []
    mail_from_l = []
    mail_subject_l = []

    for i in mail_ids:
        status, data = imap.fetch(i, '(RFC822)')

        for response_part in data:
            if isinstance(response_part, tuple):
                message = email.message_from_bytes(response_part[1])

                mail_from = message['from']
                mail_subject = message['subject']

                if message.is_multipart():
                    mail_content = ''
                    for part in message.get_payload():
                        mail_content += part.get_payload(decode=True).decode('UTF-8')
                else:
                    mail_content = message.get_payload(decode=True).decode('UTF-8')

                contents.append(mail_content)
                mail_from_l.append(mail_from)
                mail_subject_l.append(mail_subject)

    return contents, mail_from_l, mail_subject_l


def parse_text(text):
    if re.search('Incident ID:', text) == None:
        return None

    event_info = {}

    raw_loc = text.find('Raw Events')
    if raw_loc == -1:
        log.warning('No raw was provided')
    # list of {Info}: {Event}
    event_list = re.findall(r"[\w| ]*:[\w|\S_| ]*", text[:raw_loc])

    for content in event_list:
        content = content.strip().split(':')

        key = content[0]
        value = content[1:]
        value = ':'.join(value).strip()
        try:
            event_info[key] = value
            url = re.findall(
                r'https?:[0-9]+(?:\.[0-9]+){3}[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
                value)
            if url != []:
                event_info[key] = url[0]
        except KeyError as kerr:
            log.warning('Something terrible just happened, check', kerr)

    names_dict = {
        'title': ['incident title', 'title', 'event title'],
        'severity': ['event severity', 'severity', 'incident severity'],
        'date': ['date', 'incident first occurrence time', 'incident last occurrence time',
                 'time', 'timestamp', 'datetime', 'occurrence time', 'event occurrence time',
                 'incident occurrence time', 'event first occurrence time', 'event last occurrence time'],
        'status': ['status', 'incident status', 'event status'],
        'type': ['type', 'event type', 'incident type', 'category', 'incident category', 'event category'],
        'source': ['host ip', 'source ip', 'source address'],
    }

    default_names_dict = {
        'title': 'Alert',
        'severity': 2,
        'date': int(time.time()) * 1000,
        'status': 'New',
        'type': 'N/A',
        'source': 'N/A',
    }

    names_list = list(names_dict.keys())
    for key in list(event_info):
        for name in names_list:
            key_lower = key.lower()
            if key_lower in names_dict[name]:
                names_list.remove(name)
     n           event_info[name] = event_info[key]
                del event_info[key]

    for name in names_list:
        event_info[name] = default_names_dict[name]

    preparemd_raw = text[raw_loc:]
    preparemd_raw = preparemd_raw.replace('\n', '')
    preparemd_raw = preparemd_raw.replace('Raw Events', '**Raw Events**\n\n---\n\n```\n\n')
    preparemd_raw = preparemd_raw + '\n\n```\n\n---'
    event_info['Raw'] = preparemd_raw
    log.debug('Done parsing')
    return event_info


def make_alert(event_info, api, mailer, subject):
    try:
        event_info['severity'] = int(event_info['severity'])
        temp_severity = [1, 1, 1, 2, 2, 2, 2, 3, 3, 3]
        event_info['severity'] = temp_severity[event_info['severity'] - 1]
    except KeyError as kerr:
        log.error('Event Severity error', kerr)

    artifacts = []
    reserved_keys = ['title', 'severity', 'type', 'source', 'sourceRef', 'status', 'description', 'date', 'Raw']

    datatypes = ["autonomous-system", "count", "domain", "file", "filename", "fqdn",
                 "hash", "hostname", "id", "ip", "mail", "mail-subject", "organization name",
                 "other", "regexp", "registry", "remediation", "target domain", "target user group",
                 "uri_path", "url", "user", "user-agent"]

    event_info['mail'] = mailer
    event_info['mail-subject'] = subject

    if mailer is None:
        event_info['mail'] = 'Unknown email'
    if subject is None:
        event_info['mail-subject'] = 'No subject'

    for key in event_info:
        if key in reserved_keys:
            continue
        else:
            datatype = 'other'
            if key.lower() in datatypes:
                datatype = key.lower()
            if ' ip' in key.lower():
                datatype = 'ip'
            if ' id' in key.lower():
                datatype = 'id'
            if ' count' in key.lower():
                datatype = 'count'
            try:
                artifacts.append(
                    AlertArtifact(dataType=datatype, data=event_info[key], tags=[key])
                )
            except Exception as e:
                log.error('Artifact creation error', e)

    try:
        new_alert = Alert(
            title=event_info['title'],
            severity=event_info['severity'],
            type=event_info['type'],
            source=event_info['source'],
            sourceRef='email:' + str(uuid.uuid4())[0:6],
            status=event_info['status'],
            description=event_info['Raw'],
            artifacts=artifacts,
            tags=[event_info['mail'], event_info['mail-subject']]
        )
    except Exception as e:
        log.error('Alert creation error', e)
    try:
        return api.create_alert(new_alert)
    except Exception as e:
        log.error('Failed to create Alert for TheHive', e)


if __name__ == "__main__":
    FORMAT = '%(levelname)s: %(asctime)s | %(message)s'
    log.basicConfig(format=FORMAT, filename='parser.log', level=log.DEBUG)
    
    try:
        config = configparser.ConfigParser()
        config.read('config.conf')
    except Exception as e:
        log.critical('Check if something is wrong with config.conf file')
        sys.exit()
    try:
        THEHIVE_URL = config['hackday parser']['THEHIVE_URL']
        THEHIVE_API_KEY = config['hackday parser']['THEHIVE_API_KEY']
        email_username = config['hackday parser']['email_username']
        email_password = config['hackday parser']['email_password']
        whitelisted_emails = config['hackday parser']['whitelisted_emails'].replace(' ', '').split(',')
        log.debug('Config was uploaded succesfully')
    except KeyError as ke:
        log.critical('Config key error, ', ke)
        sys.exit()
    try:
        api = TheHiveApi(THEHIVE_URL, THEHIVE_API_KEY)
        log.debug('Connection to TheHive is successful')
    except Exception as e:
        log.critical('TheHive API connection establishment error', e)
    
    while True:
#         log.debug('Entered IMAP parsing infinite loop')
        try:
            imap = imaplib.IMAP4_SSL("imap.yandex.kz")
            imap.login(email_username, email_password)
            status, messages = imap.select("INBOX")
#             log.debug('Successfuly initiated IMAP connection')
            texts, mail_from_l, mail_subject_l = email_listener(imap)
        except Exception as e:
            log.error('Email Parse Failed, {}'.format(e))
            continue
        try:
            for text, mailer, subject in zip(texts, mail_from_l, mail_subject_l):
                if mailer not in whitelisted_emails:
                    log.warning('Received message from not whitelisted email: %s' % mailer)
                    continue
                log.debug('Received email, started parsing incident from email %s' % mailer)
                event_info = parse_text(text)
                if event_info != None:
                    try:
                        res = make_alert(event_info, api, mailer, subject)
                        idd = res.json()['id']
                        log.info("Created alert with ID: %s" % idd)
                    except KeyError as ke:
                        log.error('Unable to create alert,', ke, "\nEvent info:", event_info)
                else:
                    log.warning('Received email from %s with subject %s without incident' % (mailer, subject))
        except Exception as e2:
            log.error('Text parse failed, {}'.format(e2))
            continue