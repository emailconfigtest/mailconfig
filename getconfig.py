import json
import argparse
import logging
import datetime
import os
from autoconfig import autoconfig
from autodiscover import autodiscover
from srv import srv
from buildin import buildin

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOGGER = logging.getLogger(__name__)

SCAN_AUTOCONFIG = 1
SCAN_AUTODISCOVER = 2
SCAN_SRV = 4
SCAN_BUILDIN = 8

SCAN_ALL = SCAN_AUTOCONFIG | SCAN_AUTODISCOVER | SCAN_SRV | SCAN_BUILDIN

def doscan(mailaddress, domain, flag):
    """Perform email server configuration scan"""
    data = {
        "scan_info": {
            "email": mailaddress,
            "domain": domain,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "methods_used": []
        },
        "results": {}
    }

    if flag & SCAN_AUTOCONFIG:
        LOGGER.info(f"Scanning autoconfig for {domain}")
        data["scan_info"]["methods_used"].append("autoconfig")
        data["results"]["autoconfig"] = autoconfig(domain, mailaddress)
        LOGGER.info("Autoconfig scan completed")

    if flag & SCAN_AUTODISCOVER:
        LOGGER.info(f"Scanning autodiscover for {domain}")
        data["scan_info"]["methods_used"].append("autodiscover")
        data["results"]["autodiscover"] = autodiscover(domain, mailaddress)
        LOGGER.info("Autodiscover scan completed")

    if flag & SCAN_SRV:
        LOGGER.info(f"Scanning SRV records for {domain}")
        data["scan_info"]["methods_used"].append("srv")
        data["results"]["srv"] = srv(domain)
        LOGGER.info("SRV records scan completed")

    if flag & SCAN_BUILDIN:
        LOGGER.info(f"Looking up builtin provider list for {domain}")
        data["scan_info"]["methods_used"].append("buildin")
        data["results"]["buildin"] = buildin(domain)
        LOGGER.info("Builtin provider lookup completed")

    return data

def save_json_output(data, filename):
    """Save data to JSON file"""
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        LOGGER.info(f"Results saved to {filename}")
        return True
    except Exception as e:
        LOGGER.error(f"Failed to save results to {filename}: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Email server configuration detection tool')
    parser.add_argument('-a', '--mailaddress', type=str, help='Email address to scan')
    parser.add_argument('-c', '--autoconfig', action='store_true', help='Look up autoconfig')
    parser.add_argument('-d', '--autodiscover', action='store_true', help='Look up autodiscover')
    parser.add_argument('-s', '--srv', action='store_true', help='Look up DNS SRV records')
    parser.add_argument('-b', '--buildin', action='store_true', help='Look up builtin provider list')
    parser.add_argument('-o', '--json-file', type=str, help='Save output to JSON file')

    args = parser.parse_args()

    # Validate email address
    email_parts = args.mailaddress.split("@")
    if len(email_parts) != 2:
        LOGGER.error(f"Invalid email address: {args.mailaddress}")
        return 1
    
    domain = email_parts[1]
    LOGGER.info(f"Starting scan for {args.mailaddress}")

    # Determine scan flags
    flag = 0
    if args.autoconfig:
        flag |= SCAN_AUTOCONFIG
    if args.autodiscover:
        flag |= SCAN_AUTODISCOVER
    if args.srv:
        flag |= SCAN_SRV
    if args.buildin:
        flag |= SCAN_BUILDIN
    if flag == 0:
        flag = SCAN_ALL

    # Perform scan
    result = doscan(args.mailaddress, domain, flag)
    
    # Handle output
    if args.json_file:
        save_json_output(result, args.json_file)
    else:
        print(json.dumps(result, indent=2, default=str))

    LOGGER.info("Scan completed successfully")
    return 0

if __name__ == "__main__":
    exit(main())