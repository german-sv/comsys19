# Source code for the Laboratory on Communication Systems 

## Folder structure

### /MQTT/Client/
Sample client application for the ping service. Includes certificates and AWS library. Note: you can find the MQTT broker endhost inside the script.

### /MQTT/mqtt_policy.json
Contains the security policy used at the AWS Broker. Please note the selection of the clientId when connecting to the broker. Each group is required to use pl19-{group_id} to connect to the broker. 

### /MQTT/Broker/
The server application that generates ping request messages.

### /DB/ 
Contains the schema of the emplyed DB (Firebird) and the file containing initial credentials of each group.

### /WebAPI/ 
Source code of the available REST API

### /WebPortal/
Source code of the web server application

### /Lambda/
Source of the Lambda function running on AWS

## Note
The project is undergoing continuous modifications.
In case of any issue please open a topic here ot contact german.sviridov{::at::}polito{::dot::}it
