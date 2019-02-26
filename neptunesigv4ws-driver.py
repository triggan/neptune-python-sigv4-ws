# Amazon Neptune version 4 signing example (for establishing websocket connection)
#   The following script only establishes the websocket connection.  It does not submit a query.

# The following script requires python 3.6
import http.client as http_client
import sys, os, base64, datetime, hashlib, hmac
import requests # pip install requests
import urllib
import os
import json
from gremlin_python.driver import client
from gremlin_python import statics
from gremlin_python.structure.graph import Graph
from gremlin_python.process.graph_traversal import __
from gremlin_python.process.strategies import *
from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
from tornado import httpclient
from gremlin_python.process.traversal import T

# Read AWS access key from env. variables. Best practice is NOT
# to embed credentials in code.
access_key = os.getenv('AWS_ACCESS_KEY_ID', '')
secret_key = os.getenv('AWS_SECRET_ACCESS_KEY', '')
region = os.getenv('SERVICE_REGION', '')

# make sure required params are passed
program_name = sys.argv[0]
if (len(sys.argv)!=5):
    print('')
    print('+++++ USAGE +++++')
    print('> export AWS_ACCESS_KEY_ID=[MY_ACCESS_KEY_ID]')
    print('> export AWS_SECRET_ACCESS_KEY=[MY_SECRET_ACCESS_KEY]')
    print('> export SERVICE_REGION=[us-east-1|us-east-2|us-west-2|eu-west-1]')
    print('')
    print('Examples:')
    print('> python3.6 ' + program_name + ' your-neptune-endpoint:8182' )
    print('')
    print('Environment variables must be defined as AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY')
    print('')

    if (access_key == ''):
        print('!!! ERROR: Your AWS_ACCESS_KEY_ID environment variable is undefined.')
    if (secret_key == ''):
        print('!!! ERROR: Your AWS_SECRET_KEY environment variable is undefined.')
    if (region == ''):
        print('!!! ERROR: Your REGION environment variable is undefined.')
        sys.exit()


# Read command line parameters
host = sys.argv[1]
query_type = sys.argv[2]

service = 'neptune-db'
endpoint = 'http://' + host
method = 'GET'  #Forcing method GET to establish the websocket connection

print()
print('+++++ USER INPUT +++++')
print('host = ' + host)


# --------------------------- NOTE: Trialing / at the end causes issues when creating a
# --------------------------- websocket connection with the gremlin-python client.
# Set the stack and payload depending on query_type.

if (query_type == 'sparql') or (query_type == 'sparqlupdate'):
    canonical_uri = '/sparql'
elif (query_type == 'gremlin'):
    canonical_uri = '/gremlin'
else:
    print('Second parameter must be "gremlin" or "sparql", but is "' + method + '".')
    sys.exit()

# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


# ************* TASK 1: CREATE A CANONICAL REQUEST *************
# http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

# Step 1 is to define the verb (GET, POST, etc.)--already done.

# Create a date for headers and the credential string.
t = datetime.datetime.utcnow()
amzdate = t.strftime('%Y%m%dT%H%M%SZ')
datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope


# ************* TASK 1: CREATE A CANONICAL REQUEST *************
# http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

# Step 1 is to define the verb (GET, POST, etc.)--already done.
# Step 2: is to define the canonical_uri--already done.

# Step 3: Create the canonical query string. This should be an empty string for
# the purposes of establishing a websocket connection.  Once the websocket is created
# requests can be submitted to the websocket.
canonical_querystring = ''

# Step 4: Create the canonical headers and signed headers. Header names
# must be trimmed and lowercase, and sorted in code point order from
# low to high. Note that there is a trailing \n.
canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'


# Step 5: Create the list of signed headers. This lists the headers
# in the canonical_headers list, delimited with ";" and in alpha order.
# Note: The request can include any headers; canonical_headers and
# signed_headers lists those that you want to be included in the
# hash of the request. "Host" and "x-amz-date" are always required.
signed_headers = 'host;x-amz-date'

# Step 6: Create payload hash (hash of the request body content). For GET
# requests, the payload is an empty string ("").
post_payload = ''

payload_hash = hashlib.sha256(post_payload.encode('utf-8')).hexdigest()

# Step 7: Combine elements to create canonical request.
canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

# ************* TASK 2: CREATE THE STRING TO SIGN*************
# Match the algorithm to the hashing algorithm you use, either SHA-1 or
# SHA-256 (recommended)
algorithm = 'AWS4-HMAC-SHA256'
credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

# ************* TASK 3: CALCULATE THE SIGNATURE *************
# Create the signing key using the function defined above.
signing_key = getSignatureKey(secret_key, datestamp, region, service)

# Sign the string_to_sign using the signing_key
signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()


# ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
# The signing information can be either in a query string value or in
# a header named Authorization. This code shows how to use a header.
# Create authorization header and add to request headers
authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

# The request can include any headers, but MUST include "host", "x-amz-date",
# and (for this scenario) "Authorization". "host" and "x-amz-date" must
# be included in the canonical_headers and signed_headers, as noted
# earlier. Order here is not significant.
# Python note: The 'host' header is added automatically by the Python 'requests' library.
headers = {'x-amz-date':amzdate, 'Authorization':authorization_header}

# ************* SEND THE REQUEST *************
request_url = endpoint + canonical_uri

print()
print('++++ OUTPUT REQUEST PARAMETERS +++++')
print('Request URL = ' + request_url)
print('Headers = ' + json.dumps(headers))
print()
print('++++ ESTABLISH WEB SOCKET CONNECTION ++++')
websocket_url = request_url.replace("http","ws")
print('Converting Request URL from HTTP to WS: ' + websocket_url)
print('Generating a signed HTTP requests to initiate the creation of the websocket session. Using Tornado HTTP Client...')
signed_ws_request = httpclient.HTTPRequest(websocket_url, headers=headers)
print('Creating websocket connection...')
#websocketClient = client.Client(signed_ws_request, 'g')
graph = Graph()

g = graph.traversal().withRemote(DriverRemoteConnection(signed_ws_request,'g'))
#print('Websocket establishd to: ' + websocketClient._url.url)
print('Executing a count of all vertices - g.V().count()...')
#testQuery = websocketClient.submit('g.V().count()')
testQuery = g.V().groupCount().by(T.label).toList()

print("Test Result Returned: " + json.dumps(testQuery))
