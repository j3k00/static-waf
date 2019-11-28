from ModSecurity import Rules
from ModSecurity import Transaction
from ast import literal_eval
import ModSecurity
import os
import sys
import json
import base64
import csv
import argparse

# =========================== CONSTANTS ===========================

RULE_PATH = "/opt/ModSecurity/pymodsecurity/modsec_rules.conf"
CLIENT_REQUEST_USER_AGENT = "ClientRequestUserAgent"
MODSEC_FLAG = "ModSecFlag"
MODSEC_RULE_TRUE = {MODSEC_FLAG : 1}
MODSEC_RULE_FALSE = {MODSEC_FLAG : 0}

# =========================== FUNCTIONS ===========================

# Parse Request
def parseRequest(req):
    method = uri = version = ""
    method = req["ClientRequestMethod"]
    uri = req["ClientRequestHost"] + req["ClientRequestURI"]

    return method, uri, "HTTP/1.1", "", ""

# ======================== ARGUMENT PARSER ========================

parser = argparser.ArgumentParser()
parser.add_argument("-V", "--version", action="version", version="%(prog)s 1.0", help="show program version number and exit")
parser.add_argument("-i", "--input", metavar="", required = True, help = "input filename")
parser.add_argument("-o", "--output", metavar="", required = True, help ="output filename")
args = parser.parse_args()


# ======================== OPEN INPUT FILE ========================

if os.path.exists(args.input):
    wafLog = open(args.input, "r", errors='ignore')
else:
    print("Input file not found.")
    sys.exit()

# ======================== OPEN OUTPUT FILE =======================

if os.path.exists(args.output):
    choose = input("Do you want to overwirte " + args.output + "?[Y/N]"):
    if choose = "N" or choose == "n":
        sys.exit()

    os.remove(args.output)
fileCSV = open(args.output, "a+")

# ============================= MAIN ==============================

rules = Rules()
r = rules.loadFromUri(RULE_PATH)

if r == -1:
   print (rules.getParserError())
   sys.exit()

modsecurity = ModSecurity.ModSecurity()

csvColumns = []
csvColumns.append(MODSEC_FLAG)

for line in wafLog:
    requestJson = json.loads(line)
    for key in requestJson.keys():
        csvColumns.append(key)
    break
csvColumns.sort()

# Write the first line in csv file as field names
writer = csv.DictWriter(fileCSV, fieldnames = csvColumns)
writer.writeheader()

wafLog.seek(0)

for line in wafLog:
    requestJson = json.loads(line)
    transaction = ModSecurity.Transaction(modsecurity, rules, None)

    # Parse and process the request
    method, uri, version, headers, data = parseRequest(requestJson)
    transaction.processURI(uri, method, version)
    transaction.processRequestHeaders()
    transaction.processRequestBody()

    intervention = ModSecurity.ModSecurityIntervention()

    # If the request has triggered a rule, the ModSecFlag is set to 1 
    requestJson.update(MODSEC_RULE_FALSE)
    if transaction.intervention(intervention):
        requestJson.update(MODSEC_RULE_TRUE)
    json.dumps(requestJson)

    # The ClientRequesUserAgent contains commas, to avoid an incorrect 
    # rappresentation the filed in the output file is encoded in base64
    for key in sorted(requestJson.keys()):
        if(key == CLIENT_REQUEST_USER_AGENT):
            fileCSV.write("%s,"%(base64.b64encode(bytes(requestJson[key], 'UTF-8'))))
        else:
            fileCSV.write("%s,"%(requestJson[key]))
    fileCSV.write("\n")

    del transaction

fileCSV.close()
wafLog.close()