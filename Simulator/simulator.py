# import required python modules
import logging
import multiprocessing as mp
import os
import random
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor

import paho.mqtt.client as mqtt
import requests
from tomlkit import loads

executor = ThreadPoolExecutor(max_workers=5)

sourceDirectory = os.getcwd()
logging.debug("Running from: %s", sourceDirectory)

CONFIG_FILE = sourceDirectory + "\\config.toml"
HIERARCHY_FILE = sourceDirectory + "\\hierarchy.toml"

HIERARCHY_EXISTS = False

try:
    with open(CONFIG_FILE, encoding='utf-8') as f:
        config = loads(f.read())
except (FileNotFoundError, PermissionError, OSError) as e:
    exception_type, exception_object, exception_traceback = sys.exc_info()
    line_number = exception_traceback.tb_lineno

    logging.error("line %s - %s", line_number, e)

try:
    with open(HIERARCHY_FILE, encoding='utf-8') as f:
        hierarchy = loads(f.read())
    HIERARCHY_EXISTS = True
except (FileNotFoundError, PermissionError, OSError) as e:
    exception_type, exception_object, exception_traceback = sys.exc_info()
    line_number = exception_traceback.tb_lineno

    logging.error("line %s - %s", line_number, e)

loglevel = config['agent settings']['log_level']

logger = logging.getLogger()
logger.setLevel(loglevel)

log_console_formatter = logging.Formatter('%(asctime)s %(pathname)s:%(lineno)d %(message)s')

if len(logger.handlers) == 0:
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_console_formatter)
    console_handler.setLevel(loglevel)
    logger.addHandler(console_handler)
else:
    handler = logger.handlers[0]
    handler.setFormatter(log_console_formatter)

rotate_handler = RotatingFileHandler(filename=os.path.dirname(__file__) + '/agent.log', maxBytes=1000000, backupCount=5)
log_file_formatter = logging.Formatter('%(asctime)s p%(process)s %(pathname)s:%(lineno)d %(message)s')
rotate_handler.setFormatter(log_file_formatter)
rotate_handler.setLevel(loglevel)
# Log to Rotating File
logger.addHandler(rotate_handler)

# setup script variables
logging.info("Configuring agent variables")

# ---------------------------------------------------
url = config['agent settings']['url']
port = config['agent settings']['port']

clientId = config['agent settings']['deviceid']
device_name = config['agent settings']['devicename']
tenant = config['agent settings']['tenant']
username = config['agent settings']['username']
password = config['agent settings']['password']
update_rate = config['agent settings']['updaterateinseconds']

restUrl = "https://" + url

class AgentState:
    """Manages the state of the MQTT agent including JWT token and child device status."""
    
    def __init__(self):
        self.jwt_token = ""
        self.has_children = False
    
    def update_jwt_token(self, token):
        """Update the JWT token."""
        self.jwt_token = token
    
    def set_has_children(self, children_status):
        """Set whether the agent has child devices."""
        self.has_children = children_status

agent_state = AgentState()

# ---------------------------------------------------

# Set up queue that is used as workaround to paho issue
task_queue = mp.Queue()

# create mqtt client setting properties required for Cumulocity
mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, clientId, clean_session=True, userdata=None, protocol=mqtt.MQTTv311, transport="tcp")
mqttc.username_pw_set(tenant + "/" + username, password)


def on_connect(client, userdata, flags, rc, properties=None):
    """Handle MQTT connection callback."""
    _ = userdata, flags, properties  # Suppress unused parameter warnings
    if rc == 0:
        logging.info("Connection established - RC: %s", rc)
        client.connected_flag = True
        client.subscribe("s/ds")
    else:
        logging.error("Connection failed - RC: %s", rc)


def on_message(client, userdata, message, properties=None):
    """Handle MQTT message callback."""
    _ = client, userdata, properties  # Suppress unused parameter warnings
    topic = message.topic
    payload = message.payload.decode()
    logging.info("Received message on topic: %s, payload: %s", topic, payload)

    # setting up operation handlers
    if payload.startswith("510"):
        # Handle restart for parent or child device
        device_id = payload.split(",")[1]
        task_queue.put([perform_restart, device_id])
    if payload.startswith("515"):
        _, device_id, firmware_name, firmware_version, firmware_url = payload.split(",")
        executor.submit(perform_firmware_update, device_id, firmware_name, firmware_version, firmware_url)
    if payload.startswith("71"):
        agent_state.jwt_token = payload.split(',')[1]

def on_publish(client, userdata, mid, properties=None):
    """Handle MQTT publish callback."""
    _ = client, userdata, properties  # Suppress unused parameter warnings
    logging.info(" MESSAGE PUBLISHED: %s", mid)

def on_subscribe(client, obj, mid, granted_qos, properties=None):
    """Handle MQTT subscription callback."""
    _ = client, obj, properties  # Suppress unused parameter warnings
    logging.info("SUBSCRIBED (ACK): MID=%s, QOS=%s", mid, granted_qos)

def on_log(client, userdata, level, buf, properties=None):
    """Handle MQTT logging callback."""
    _ = client, userdata, level, properties  # Suppress unused parameter warnings
    logging.info("log: %s", buf)


def random_past_date(days, start=1):
    """Generate a random date in the past within the specified range.
    
    Args:
        days (int): Maximum number of days in the past
        start (int): Minimum number of days in the past (default: 1)
        
    Returns:
        str: Random date in YYYY-MM-DD format
    """
    current_timestamp = time.time()
    seconds_in_a_day = 60 * 60 * 24
    random_seconds = random.randint(start, days) * seconds_in_a_day
    random_timestamp = current_timestamp - random_seconds
    random_date = time.strftime("%Y-%m-%d", time.localtime(random_timestamp))
    return random_date

def registration():
    """Register the device and its child devices with Cumulocity IoT platform."""
    # register device using smart template 100
    publish("s/us", "100," + device_name + ",c8y_MQTTDevice,", wait_for_ack=True)
    # Update device details
    publish("s/us", "110,28-135504,Commercial Agent,Rev1.0")
    # identify supported operations
    publish("s/us", "114,c8y_Restart,c8y_LogfileRequest,c8y_Firmware")
    # Set availability and required interval to 1 minute
    publish("s/us", "117,10")
    # register logs supported on device
    publish("s/us", "118,agentLog")

    if HIERARCHY_EXISTS:
        for child_device in hierarchy["childDevices"]:
            publish("s/us", "101," + str(child_device["id"]) + "," + child_device["name"] + "," + child_device["type"], wait_for_ack=True)
            publish("s/us/" + str(child_device["id"]), "110," + child_device["serial"] + "," + child_device["model"] + "," + child_device["revision"])
            publish("s/us/" + str(child_device["id"]), "114,c8y_Restart,c8y_Firmware")
            publish("s/us/" + str(child_device["id"]), "115," + child_device["firmwareName"] + "," + child_device["firmwareVersion"])
            publish("s/us/" + str(child_device["id"]), "117,15")

            logging.info("Device %s registered successfully", child_device["name"])
            agent_state.has_children = True

    mqttc.registered_flag = True
    logging.info("Parent device registered successfully")


def perform_restart(device_id):
    """Perform restart operation for a device.
    
    Args:
        device_id (str): ID of the device to restart
    """
    logging.info("RESTART REQUESTED...")
    publish("s/us/" + device_id, "501,c8y_Restart", wait_for_ack=True)

    logging.info("...restarting...")
    time.sleep(5)

    publish("s/us/" + device_id, "503,c8y_Restart", wait_for_ack=True)
    logging.info("...RESTART COMPLETE")


def perform_firmware_update(device_id, firmware_name, firmware_version, firmware_url):
    """Perform firmware update operation for a device.
    
    Args:
        device_id (str): ID of the device to update
        firmware_name (str): Name of the firmware
        firmware_version (str): Version of the firmware
        firmware_url (str): URL of the firmware (currently unused)
    """
    logging.info("Firmware update requested to %s (%s) from %s", firmware_version, firmware_name, firmware_url)
    publish("s/us/" + device_id, "501,c8y_Firmware", wait_for_ack=True)
    time.sleep(4)
    publish("s/us/" + device_id, "115," + firmware_name + "," + firmware_version)
    time.sleep(4)
    publish("s/us/" + device_id, f"503,c8y_Firmware,{firmware_name},{firmware_version},{firmware_url}", wait_for_ack=True)



def send_measurement():
    """Send measurement data for both gateway device and child devices."""
    hourstoadd = simulate(0, 5)

    if agent_state.has_children:
        for child_device in hierarchy["childDevices"]:
            publish("s/us/" + str(child_device["id"]), "200,Hours,Hours," + str(hourstoadd) + ",Hrs")
            if child_device["measurements"]:
                for measurement in child_device["measurements"]:
                    logging.debug("SENDING: %s for child device...", measurement["type"])
                    publish("s/us/" + str(child_device["id"]),
                            "200," + measurement["type"] + "," + measurement["series"] + "," + str(
                                simulate(measurement["min"], measurement["max"], 2)) + "," + measurement[
                                "units"])

    if config["measurements"]:
        for measurement in config["measurements"]:
            logging.debug("SENDING: %s for gateway device...", measurement["type"])
            publish("s/us", "200," + measurement["type"] + "," + measurement["series"] + "," + str(
                simulate(measurement["min"], measurement["max"], 2)) + "," + measurement["units"])
    else:
        publish("s/us", "211," + str(simulate(15, 35, 2)))
        publish("s/us", "200,Humidity,Humidity," + str(simulate(15, 35, 2)) + ",%")


def simulate(min_value, max_value, decimals=0):
    '''Generate a random value within the specified range.
    
    Args:
        min_value (float): Minimum value
        max_value (float): Maximum value
        decimals (int): Number of decimal places (default: 0)
        
    Returns:
        float: Random value
    '''
    return round(random.uniform(min_value, max_value), decimals)


def publish(topic, message, wait_for_ack=False):
    '''Publish a message to the specified topic.
    
    Args:
        topic (str): Topic to publish to
        message (str): Message to publish
        wait_for_ack (bool): Whether to wait for acknowledgement (default: False)
    '''
    logging.info("PUBLISHING: Message - " + message + " || Topic: " + topic)
    qos = 2 if wait_for_ack else 0
    message_info = mqttc.publish(topic, message, qos)
    if wait_for_ack:
        logging.debug(" > awaiting ACK for  %s", message_info.mid)
        message_info.wait_for_publish()
        logging.debug(" < received ACK for  %s", message_info.mid)

def device_loop():
    '''Main loop to send measurements at specified interval.'''
    while True:
        task_queue.put([send_measurement])
        time.sleep(update_rate)


def main():
    '''Main function to run the simulator.'''
    mqttc.connected_flag = False
    mqttc.registered_flag = False

    # register call backs
    mqttc.on_connect = on_connect
    mqttc.on_message = on_message
    # mqttc.on_publish = on_publish
    mqttc.on_subscribe = on_subscribe
    # mqttc.on_log = on_log

    # start work
    logging.info("Connecting to broker %s", url)
    mqttc.loop_start()
    mqttc.connect(str(url), int(port))

    # stay here until connected
    while not mqttc.connected_flag:
        logging.info("...")
        time.sleep(1)

    logging.info("Registering device...")
    registration()
    while not mqttc.registered_flag:
        logging.info("...")
        time.sleep(1)

    publish("s/uat", "")

    # multithreading support
    device_loop_thread = threading.Thread(target=device_loop)
    device_loop_thread.daemon = True
    device_loop_thread.start()

    # process all tasks currently in queue
    try:
        while True:
            items = task_queue.get()
            func = items[0]
            args = items[1:]
            func(*args)
    except (KeyboardInterrupt, SystemExit):
        logging.error("Received keyboard interrupt, quitting ...")
        exit(0)


if __name__ == "__main__":
    main()
