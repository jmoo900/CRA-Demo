"""
Firmware Scanner Integration Module

This module integrates Azure IoT Firmware Scanner with Cumulocity IoT platform
to scan firmware for vulnerabilities and manage device alarms based on CVE findings.
"""
import json
from datetime import datetime, timezone
import urllib.parse
import random
import requests
from packaging import version as semver

# Load config
with open('config.json', 'r', encoding='utf-8') as f:
    config = json.load(f)

# Azure Config
TENANT_ID = config["azure"]["tenant_id"]
CLIENT_ID = config["azure"]["client_id"]
CLIENT_SECRET = config["azure"]["client_secret"]
SUBSCRIPTION_ID = config["azure"]["subscription_id"]
RESOURCE_GROUP = config["azure"]["resource_group"]
WORKSPACE_NAME = config["azure"]["workspace_name"]
FIRMWARE_ID = config["azure"]["firmware_id"]
SUMMARY_TYPE_NAME = config["azure"]["summary_type_name"]
API_VERSION = config["azure"]["api_version"]

# Cumulocity Config
C8Y_BASE_URL = config["cumulocity"]["base_url"]
C8Y_TENANT = config["cumulocity"]["tenant"]
C8Y_USER = config["cumulocity"]["user"]
C8Y_PASSWORD = config["cumulocity"]["password"]
ALARM_TYPE = config["cumulocity"]["alarm_type"]
ALARM_SEVERITY = config["cumulocity"]["alarm_severity"]

# -------------Initialization to reset all firmware risk values-------------------
def setup_reset_risk_for_all(family_model, scanned_version):
    """
    Demo setup:
    - Same-family older versions => major or critical
    - Different family => none or marginal
    Additionally, this function now finds devices with older firmware
    and creates new alarms with random CVE properties.
    """
    query = urllib.parse.quote("type eq 'c8y_FirmwareBinary'")
    url = f"{C8Y_BASE_URL}/inventory/managedObjects?pageSize=2000&withParents=true&query={query}"
    auth = (f"{C8Y_TENANT}/{C8Y_USER}", C8Y_PASSWORD)

    r = requests.get(url, auth=auth, timeout=30)
    r.raise_for_status()
    mos = r.json().get("managedObjects", [])

    for mo in mos:
        fw_version = mo.get("c8y_Firmware", {}).get("version")
        if not fw_version:
            continue

        # Determine firmware family name from its parent
        parents = mo.get("additionParents", {}).get("references", [])
        mo_family = None
        if parents:
            mo_family = parents[0].get("managedObject", {}).get("name")

        if mo_family == family_model:
            # Same model family
            if semver.parse(fw_version) < semver.parse(scanned_version):
                # This is an older version.
                # First, set the simulated risk.
                simulated_risk = random.choice(["high", "critical"])
                _set_fw_risk(mo["id"], simulated_risk)
                print(f"ℹ️ Same-family older version {mo_family} {fw_version} set to {simulated_risk}")

                # Now, find all devices with this older firmware and create an alarm for them.
                older_devices = find_devices_with_firmware(mo_family, fw_version)
                print(f"ℹ️ Found {len(older_devices)} device(s) using older firmware {mo_family} v{fw_version}.")

                # Generate random CVE properties for the alarm
                random_properties = generate_random_cve_properties()

                # Always create an alarm for older firmware versions
                for dev in older_devices:
                    create_alarm_on_device(dev["id"], random_properties)
                    print(f"✅ Alarm created for older firmware on device {dev['name']} ({dev['id']})")

            else:
                # Skip scanned and newer versions
                continue
        else:
            # Other families: keep variability but not too high
            simulated_risk = random.choice(["none", "low"])
            _set_fw_risk(mo["id"], simulated_risk)
            print(f"ℹ️ Non-family FW ({mo_family}) {fw_version} set to {simulated_risk}")


def generate_random_cve_properties():
    """Generates a dictionary with random counts for various CVE severities."""
    return {
        "criticalCveCount": random.randint(0, 3),
        "highCveCount": random.randint(0, 7),
        "mediumCveCount": random.randint(0, 10),
        "lowCveCount": random.randint(0, 5),
        "unknownCveCount": random.randint(0, 4)
    }


# ----------sets the risk level on firmware binary MO-------------
def _set_fw_risk(fw_mo_id, risk_level):
    """Helper to PATCH risk attribute on a firmware binary MO."""
    update_payload = {"securityRisk": risk_level}
    put_url = f"{C8Y_BASE_URL}/inventory/managedObjects/{fw_mo_id}"
    auth = (f"{C8Y_TENANT}/{C8Y_USER}", C8Y_PASSWORD)
    r = requests.put(put_url, auth=auth, json=update_payload, timeout=30)
    r.raise_for_status()


# ------------ Azure Auth ------------
def get_access_token():
    """Acquire Azure AD access token for Azure Management API."""
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    payload = {
        'client_id': CLIENT_ID,
        'scope': 'https://management.azure.com/.default',
        'client_secret': CLIENT_SECRET,
        'grant_type': 'client_credentials'
    }
    r = requests.post(url, data=payload, timeout=30)
    r.raise_for_status()
    return r.json()['access_token']


# ------------ Azure: Get Firmware Metadata ------------
def get_firmware_metadata(access_token):
    """Fetch Azure firmware metadata including model and version."""
    url = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.IoTFirmwareDefense"
        f"/workspaces/{WORKSPACE_NAME}"
        f"/firmwares/{FIRMWARE_ID}?api-version={API_VERSION}"
    )
    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()
    props = data.get("properties", {})
    model = props.get("model")
    version = props.get("version")
    return model, version


# ------------ Azure API Call for CVE Summary ------------
def get_firmware_cve_summary(access_token):
    """Fetch Azure firmware CVE summary."""
    url = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.IoTFirmwareDefense"
        f"/workspaces/{WORKSPACE_NAME}"
        f"/firmwares/{FIRMWARE_ID}"
        f"/summaries/{SUMMARY_TYPE_NAME}?api-version={API_VERSION}"
    )
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()


# ------------ Find FirmwareBinary by Model + Version ------------
def find_firmware_binary_by_model_and_version(model, version):
    """Find firmware binary managed object by model and version."""
    query = urllib.parse.quote(f"type eq 'c8y_FirmwareBinary' and c8y_Firmware.version eq '{version}'")
    url = f"{C8Y_BASE_URL}/inventory/managedObjects?pageSize=2000&withParents=true&query={query}"
    auth = (f"{C8Y_TENANT}/{C8Y_USER}", C8Y_PASSWORD)
    r = requests.get(url, auth=auth, timeout=30)
    r.raise_for_status()
    mos = r.json().get("managedObjects", [])
    for mo in mos:
        parents = mo.get("additionParents", {}).get("references", [])
        for ref in parents:
            parent_mo = ref.get("managedObject", {})
            if parent_mo.get("name") == model:
                return mo
    return None


# ------------ Update FirmwareBinary MO with Scan ------------
def update_firmware_binary_with_scan(firmware_mo, azure_scan_info, scan_data):
    """Update firmware binary managed object with scan results."""
    fw_mo_id = firmware_mo["id"]
    # Check if scanResults exists and is a list. If not, initialize it.
    existing_results = firmware_mo.get("scanResults", [])
    if not isinstance(existing_results, list):
        existing_results = []

    # Append the new scan entry to the list
    existing_results.append(scan_data)

    risk = calculate_risk(scan_data["result"])

    update_payload = {
        "azureScanInfo": azure_scan_info,
        "scanResults": existing_results,
        "latestScan": scan_data,
        "securityRisk": risk
    }

    url = f"{C8Y_BASE_URL}/inventory/managedObjects/{fw_mo_id}"
    auth = (f"{C8Y_TENANT}/{C8Y_USER}", C8Y_PASSWORD)
    r = requests.put(url, auth=auth, json=update_payload, timeout=30)
    r.raise_for_status()
    return fw_mo_id


# ------------- Calculate the risk for firmware after scan --------------
def calculate_risk(cve_properties):
    """Calculate firmware risk level based on CVE counts."""
    if cve_properties.get("criticalCveCount", 0) > 0:
        return "critical"
    elif cve_properties.get("highCveCount", 0) >= 3:
        return "major"
    elif cve_properties.get("mediumCveCount", 0) >= 3:
        return "marginal"
    else:
        return "none"


# ------------ Find Devices Running This FW ------------
def find_devices_with_firmware(model, version):
    """Find devices running specific firmware model and version."""
    query = urllib.parse.quote(f"c8y_Firmware.name eq '{model}' and c8y_Firmware.version eq '{version}'")
    url = f"{C8Y_BASE_URL}/inventory/managedObjects?pageSize=2000&query={query}"
    auth = (f"{C8Y_TENANT}/{C8Y_USER}", C8Y_PASSWORD)
    r = requests.get(url, auth=auth, timeout=30)
    r.raise_for_status()
    return r.json().get("managedObjects", [])


# ------------ Create Alarm on Device ------------
def create_alarm_on_device(device_id, cve_properties):
    """Create alarm on device with specific CVE properties."""
    url = f"{C8Y_BASE_URL}/alarm/alarms"
    auth = (f"{C8Y_TENANT}/{C8Y_USER}", C8Y_PASSWORD)
    alarm_payload = {
        "source": {"id": device_id},
        "type": ALARM_TYPE,
        "text": (
            f"CVE Summary - Critical:{cve_properties.get('criticalCveCount', 0)}, "
            f"High:{cve_properties.get('highCveCount', 0)}, "
            f"Medium:{cve_properties.get('mediumCveCount', 0)}, "
            f"Low:{cve_properties.get('lowCveCount', 0)}, "
            f"Unknown:{cve_properties.get('unknownCveCount', 0)}"
        ),
        "severity": ALARM_SEVERITY,
        "status": "ACTIVE",
        "time": datetime.now(timezone.utc).isoformat(),
        "cveSummary": cve_properties
    }
    r = requests.post(url, auth=auth, json=alarm_payload, timeout=30)
    r.raise_for_status()


# ------------ MAIN ------------
if __name__ == "__main__":
    try:
        # 1. Auth to Azure
        token = get_access_token()
        print("✅ Azure AD token acquired.")

        # 2. Get firmware metadata from Azure
        firmware_model, firmware_version = get_firmware_metadata(token)
        if not firmware_model or not firmware_version:
            raise ValueError("Could not retrieve model/version from Azure firmware metadata")
        print(f"ℹ️ Firmware model from Azure: {firmware_model}, version: {firmware_version}")

        # 2.B Find and update all firmware binaries, creating alarms for older versions
        setup_reset_risk_for_all(firmware_model, firmware_version)

        # 3. Get CVE summary from Azure for the currently scanned firmware
        summary = get_firmware_cve_summary(token)
        print("✅ Firmware CVE summary retrieved.")
        properties = summary.get("properties", {})

        azure_ids = {
            "subscriptionId": SUBSCRIPTION_ID,
            "resourceGroup": RESOURCE_GROUP,
            "workspaceName": WORKSPACE_NAME,
            "firmwareId": FIRMWARE_ID,
            "summaryType": SUMMARY_TYPE_NAME,
            "apiVersion": API_VERSION,
            "model": firmware_model,
            "version": firmware_version
        }
        scan_entry = {
            "date": datetime.now(timezone.utc).isoformat(),
            "result": properties
        }

        # Only create an alarm if the properties are critical
        if calculate_risk(properties) == "critical":
            # 4. Find C8Y firmware binary for the scanned version
            fw_binary_mo = find_firmware_binary_by_model_and_version(firmware_model, firmware_version)
            if not fw_binary_mo:
                print(f"❌ Firmware binary not found in C8Y for model '{firmware_model}' v{firmware_version}")
                exit(1)

            # 5. Update firmware binary MO with scan results
            firmware_mo_id = update_firmware_binary_with_scan(fw_binary_mo, azure_ids, scan_entry)
            print(f"✅ Updated FirmwareBinary MO {firmware_mo_id} with latest scan results.")

            # 6. Find devices running this firmware
            devices = find_devices_with_firmware(firmware_model, firmware_version)
            print(f"ℹ️ Found {len(devices)} device(s) using this firmware.")

            # 7. Create alarms on each device for the currently scanned firmware
            for device in devices:
                create_alarm_on_device(device["id"], properties)
                print(f"✅ Alarm created on device {device['name']} ({device['id']})")
        else:
            print("ℹ️ The latest scanned firmware has no critical vulnerabilities. No alarm was created.")


    except requests.HTTPError as e:
        print(f"HTTP error: {e.response.status_code} - {e.response.text}")
    except (ValueError, KeyError, ConnectionError) as ex:
        print(f"❌ Error: {str(ex)}")
