import base64
import json
import logging
import requests
import os
import datetime as dt

from urllib.error import HTTPError, URLError
from googleapiclient import errors, discovery
from IPy import IP
from pytz import timezone
from oauth2client.client import GoogleCredentials

MAX_PORTS_OPEN = 20

logger = logging.getLogger()

# The Slack hook to use
SLACK_HOOK_URL = os.environ.get('SLACK_WEBHOOK')

# The Slack channel to send a message to stored in the slackChannel environment variable
SLACK_CHANNEL = os.environ.get('SLACK_CHANNEL', 'N/A')

# The Slack Bot Name to send a message to stored in the SLACK_NAME environment variable
SLACK_NAME = os.environ.get('SLACK_NAME', 'N/A')

GOOGLE_CREDS = GoogleCredentials.get_application_default()


def generate_gcp_link(project, fw_rule_name):
    return "https://console.cloud.google.com/networking/firewalls/details/{fw_name}?project={proj_id}".format(
        fw_name=fw_rule_name, proj_id=project)


def notify(msg):
    if msg is False:
        return
    slack_message = ""
    try:
        slack_message = {
            'attachments': [{
                "color": "#da532c",
                "fields": [
                    {
                        "title": "Firewall Name",
                        "value": msg["FW_NAME"],
                        "short": True
                    },
                    {
                        "title": "Project",
                        "value": msg["PROJECT"],
                        "short": True
                    },
                    {
                        "title": "Network",
                        "value": msg["NETWORK"],
                        "short": True
                    },
                    {
                        "title": "Creation Time",
                        "value": msg["C_TIME"],
                        "short": True
                    },
                    {
                        "title": "Description",
                        "value": msg["DESC"],
                        "short": True
                    },
                    {
                        "title": "User",
                        "value": msg['USER'],
                        "short": True
                    }

                ]
            }],
            "blocks": [
                {
                    "type": "section",
                    "block_id": "section567",
                    "text": {
                        "type": "mrkdwn",
                        "text": "{}\n\nLink to Firewall Rule: <{}|{}>\n\nFirewall Details: ".format(msg["INFO"],
                                                                                                    msg["LINK"],
                                                                                                    msg["FW_NAME"])
                    }
                }
            ]
        }
    except Exception as e:
        logger.error(str(e))
    if SLACK_CHANNEL is not 'N/A':
        slack_message['channel'] = SLACK_CHANNEL
    if SLACK_NAME is not 'N/A':
        slack_message['username'] = SLACK_NAME
    try:
        print("""
        SLACK_HOOK_URL: {}
        """.format(SLACK_HOOK_URL))
        response = requests.post(SLACK_HOOK_URL, json=slack_message)
        print(response)
        logger.info('Message posted to % s ', slack_message['channel'])
    except HTTPError as e:
        logger.error('Unable to publish message:' + msg)
        logger.error('Request failed: % d % s ', e.code, e.reason)
    except URLError as e:
        logger.error('Unable to publish message:' + msg)
        logger.error('Server connection failed: % s ', e.reason)


def extract_info_from_event(event):
    # Get the Pub/Sub message from the event and load object in JSON
    pubsub_message = base64.b64decode(event['data']).decode('utf-8')
    m = json.loads(pubsub_message)
    try:
        # decode the project and firewall rule that's changed
        project = m.get('asset').get('name').split("/")[4]
        fwrule = m.get('asset').get('name').split("/")[7]
    except KeyError as kerror:
        logging.error("[Key error] Unable to extract project/firewall rule from event.\n {}".format(str(kerror)))
        return
    return project, fwrule


def execute_request(req):
    """
    Executes the request and handles exceptions.
    :param req: Request
    :return: Response
    """
    response = None
    try:
        logger.debug("Trying to execute the following request: {}".format(str(req)))
        response = req.execute()
    except errors.HttpError as e:
        if "HttpError 403" in str(e):
            logging.error("[Authorization error] Need following permissions to execute this function: "
                          "compute.firewalls.get, compute.globalOperations.list")
    except Exception as e:
        print(str(e))
    return response


def get_firewall_rule(project, fw_rule_name):
    # Setup credentials and API
    service = discovery.build('compute', 'v1', credentials=GOOGLE_CREDS, cache_discovery=False)
    request = service.firewalls().get(project=project, firewall=fw_rule_name)
    fw_rule = execute_request(request)
    return fw_rule


def get_user_ops(target_link):
    user = "N/A"
    operation = "N/A"
    project = target_link.split("projects")[-1].split("/")[1]
    filter_target_link = "targetLink=\"{}\"".format(target_link)
    service = discovery.build('compute', 'v1', credentials=GOOGLE_CREDS, cache_discovery=False)
    request = service.globalOperations().list(
        project=project,
        filter=filter_target_link
    )

    event_details = execute_request(request)
    logger.debug("Event List: {}".format(str(event_details)))
    for event in event_details['items']:
        if event["operationType"] in ["insert", "patch"]:
            user = event["user"]
            operation = event["operationType"]
    # This will get the last event on the firewall which is insert or update.
    return user, operation


def verify_firewall_rule(fw_rule):
    secured = True
    # If firewall rule is no longer present.
    if fw_rule is None:
        return
    user_id, operation = get_user_ops(fw_rule.get('selfLink'))
    if operation == "insert":
        operation = "created"
    elif operation == "patch":
        operation = "updated"

    m = ""
    if not fw_rule.get('disabled'):  # if it's already disable then skip it
        if fw_rule.get('direction') == "INGRESS":  # if it's not an ingress rule then skip it
            # 1. Check if any source ranges are 0.0.0.0
            for source_range in fw_rule['sourceRanges']:
                ip = IP(source_range)
                if source_range == "0.0.0.0/0":
                    secured = False
                    m = "source IP range open"
                    break
            for portRules in fw_rule.get('allowed'):
                # 2. Check if all ports are open
                if portRules.get('IPProtocol') == "all":
                    secured = False
                    m = "all ports open"
                    break
                # 3. Check if all ports are open for specific protocols for non-private IP addresses
                if portRules.get('IPProtocol') in ["tcp", "udp"] and ip.iptype() != 'PRIVATE':
                    if portRules.get('ports') is None:
                        secured = False
                        m = "all " + str(portRules['IPProtocol']).upper() + " ports open"
                    else:  # We have ports to check
                        for ports in portRules.get('ports'):
                            port_list = ports.split("-")
                            if ((len(port_list)) > 1) and (int(port_list[1]) - int(port_list[0])) > MAX_PORTS_OPEN:
                                secured = False
                                m = "too many " + str(portRules.get('IPProtocol')).upper() + " ports open"

    if not secured:
        m = m if m != "" else "N/A"
        message = {}
        message['FW_NAME'] = fw_rule.get('name')
        message['PROJECT'] = fw_rule.get('selfLink').split('/')[-4]
        message['DESC'] = fw_rule.get('description') if fw_rule.get('description') != "" else "N/A"
        message['NETWORK'] = fw_rule.get('network').split('/')[-1]
        message['LINK'] = generate_gcp_link(message['PROJECT'], message['FW_NAME'])
        ts = dt.datetime.strptime(fw_rule.get('creationTimestamp'), '%Y-%m-%dT%H:%M:%S.%f%z')
        message['C_TIME'] = ts.astimezone(timezone('Asia/Kolkata')).strftime("%d/%m/%Y - %I:%M %p")
        message['USER'] = user_id
        message['INFO'] = ":warning:  Firewall rule {ops} with {msg}.".format(ops=operation, msg=m)
        print(message['INFO'])
        return message
    else:
        return False


def get_time(time_in_string):
    ts = dt.datetime.strptime(time_in_string, '%Y-%m-%dT%H:%M:%S.%f%z')
    return ts.astimezone(timezone('Asia/Kolkata'))


def run(event, context):
    logger.setLevel(os.environ.get("LOGLEVEL", "DEBUG"))
    logger.info("Event Received:")
    logger.info(event)
    gcp_project, fw_rule_name = extract_info_from_event(event)
    logger.debug("Project: {}, FW_RULE: {}".format(gcp_project, fw_rule_name))
    firewall_rule = get_firewall_rule(gcp_project, fw_rule_name)
    logger.debug("FW_RULE: {}".format(firewall_rule))
    message = verify_firewall_rule(firewall_rule)
    logger.debug("message: {}".format(message))
    if message is not None:
        logger.debug("Message is: \n " + str(message))
        notify(message)
