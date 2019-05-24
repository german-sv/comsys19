import json
from botocore.vendored import requests

def sendToWS(event):
    API_URI = "http://ec2-34-220-162-82.us-west-2.compute.amazonaws.com:5002/"
    response = requests.post(API_URI+"auth", data=json.dumps({'username':'aws', 'password':secret}), headers={'Content-Type': 'application/json'})
    
    if not json.loads(response.text)['access_token']:
    	print "Could not obtain the API_TOKEN!"
    	exit()
    
    API_TOKEN = json.loads(response.text)['access_token']

    response = requests.post(API_URI+"user/0/logs", data=json.dumps(event), headers={"Authorization": "JWT " + API_TOKEN, 'Content-Type': 'application/json'})
    
    return json.load(response)

def handler(event, context):
    return sendToWS(event)
