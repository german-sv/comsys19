from flask import Flask, request
from flask_restful import Resource, Api
import sqlalchemy
import fdb
import json
from flask_jwt import JWT, jwt_required, current_identity
from werkzeug.security import safe_str_cmp
import firebirdsql
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

## Flask instance
app = Flask(__name__)
api = Api(app)
app.config['PROPAGATE_EXCEPTIONS'] = True

## DB Setting
db_host = "localhost"
db_userName = "sysdba"
f=open("/home/ubuntu/masterPassword","r")

db_password = f.readline().rstrip("\n\r")
db_name = "//home/ubuntu/DB/pl19.fdb"
fdb_uri = 'firebird+fdb://'+db_userName+':'+db_password+'@'+db_host+''+db_name
engine = sqlalchemy.create_engine(fdb_uri)
app.config['SQLALCHEMY_DATABASE_URI'] = fdb_uri
db = SQLAlchemy(app)

GOOD_CALL = 200
BAD_CALL = 400

## Error handling
class ErrorFactory():
    @staticmethod
    def make_error(message, status_code=500, sub_code=0, action="Check the documentation on the portale."):
        response = {
            'status_code': status_code,
            'sub_code': sub_code,
            'error': message,
            'description': action
        }
        response['status_code'] = status_code
        return response
    
    @staticmethod
    def db_severe_error():
        response = {
            'status_code': 500,
            'sub_code': 0,
            'error': "This should not happen...",
            'description': "Contact German with details ASAP"
        }
        return response

# DB schemas
class Customers(db.Model):
    id = db.Column('id', db.Integer, primary_key = True)
    group_id = db.Column(db.Text())
    group_psw = db.Column(db.Text())  
    group_info = db.Column(db.Text())
    configuration = db.relationship('Configuration', backref='customers', lazy=True, uselist=False)

class Logs(db.Model):
    id = db.Column('id', db.Integer, primary_key = True)
    device_id = db.Column(db.Integer(), db.ForeignKey('configuration.id'))
    timestamp_srv = db.Column(db.DateTime())
    timestamp_dev = db.Column(db.DateTime())
    event_id = db.Column(db.Integer())
    event = db.Column(db.Text())


class Extensions(db.Model):
    id = db.Column('id', db.Integer, primary_key = True)
    device_id = db.Column(db.Integer(), db.ForeignKey('configuration.id'))
    extension_id = db.Column(db.Integer())
    extension_description = db.Column(db.Text())

class Configuration(db.Model):    
    id = db.Column('id', db.Integer, primary_key = True)
    customer_id  = db.Column(db.Integer(), db.ForeignKey('customers.id'))
    device_mac = db.Column(db.Text())
    device_status = db.Column(db.Integer())
    nickname = db.Column(db.Text())
    configuration = db.Column(db.Text())
    extensions = db.relationship('Extensions', backref='configuration', lazy=True, uselist=False)
    logs = db.relationship('Logs', backref='configuration', lazy=True, uselist=False)

    _hidden_fields = [
        "customer_id",
    ]

## JWT Authentication 
class JWTAuthenticator():
    @staticmethod
    def authenticate(username, password):
        user = Customers.query.filter_by(group_id=username).first()
        if user and safe_str_cmp(user.group_psw.encode('utf-8'), password.encode('utf-8')):
            return user
    
    @staticmethod
    def identity(payload):
        user_id = payload['identity']
        return Customers.query.filter_by(id=user_id).first()

# Update user info
class UserInformationUpdate(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        print data
        user = Customers.query.filter_by(group_id=data['group_id']).first()
        
        if len(data['group_psw_new']) > 0:
            if user and safe_str_cmp(user.group_psw.encode('utf-8'), data['group_psw'].encode('utf-8')):
                result = {'code' : GOOD_CALL, 'message' : 'Password updated!'}
                user.group_psw = data['group_psw_new']
        
        user.group_info = data['group_info']
        db.session.commit()
        result = {'code' : GOOD_CALL, 'message' : 'Group information updated'}
        return json.dumps(result)


class UserInformation(Resource):
    @jwt_required()      
    def get(self, group_id):
        if UserInformation.isAdmin(Customers.query.filter_by(id=current_identity.id).first().group_id):
            user = Customers.query.filter_by(group_id=group_id).first()
            result = {"group_id" : user.group_id, "group_psw" : user.group_psw, "group_info" : user.group_info}
        else:
            user = Customers.query.filter_by(id=current_identity.id).first()
            result = {"group_id" : user.group_id, "group_psw" : user.group_psw, "group_info" : user.group_info}

        return json.dumps(result)

    @jwt_required()
    def post(self, group_id):
        data = request.get_json()
        print data
        user = Customers.query.filter_by(group_id=data['group_id']).first()
        
        if 'group_psw_new' in data:
            if len(data['group_psw_new']) > 0:
                if user and safe_str_cmp(user.group_psw.encode('utf-8'), data['group_psw'].encode('utf-8')):
                    result = {'code' : GOOD_CALL, 'message' : 'Password updated!'}
                    user.group_psw = data['group_psw_new']
        
        user.group_info = data['group_info']
        db.session.commit()
        result = {'code' : GOOD_CALL, 'message' : 'Group information updated'}
        return json.dumps(result)

    @staticmethod
    def isAdmin(group_id):
        if group_id in ["admin", "german", "aws", "guido"]:
            return True
        return False

# Verifies the credentials.
class VerifyCredentials(Resource):
    def post(self):
        result = {'code' : 400, 'message' : 'User credentials are invalid'}
        data = request.get_json()
        user = Customers.query.filter_by(group_id=data['group_id']).first()
        if user and safe_str_cmp(user.group_psw.encode('utf-8'), data['group_psw'].encode('utf-8')):
            result = {'code' : GOOD_CALL, 'message' : 'User credentials are valid'}
        return json.dumps(result)
    

## APIs
class DeviceConfiguration(Resource):
    @jwt_required()
    def get(self, group_id):
        if UserInformation.isAdmin(Customers.query.filter_by(id=current_identity.id).first().group_id):
            user = Customers.query.filter_by(group_id=group_id).first()
            result = {'status' : GOOD_CALL, 'data': DeviceConfiguration.getJsonConfig(user.configuration)}
        else:
            user = Customers.query.filter_by(id=current_identity.id).first()
            result = {'status' : GOOD_CALL, 'data': DeviceConfiguration.getJsonConfig(user.configuration)}
        return json.dumps(result)

    @jwt_required()
    def post(self, group_id):
        data = request.get_json()

        config = Customers.query.filter_by(id=current_identity.id).first().configuration
        if 'device_mac' not in data or 'configuration' not in data or 'nickname' not in data:
            return ErrorFactory.make_error(message="Parameters missing for the configuration update.")
        config.device_mac = str(data['device_mac'])
        config.nickname = str(data['nickname'])
        config.configuration = str(data['configuration'])
        db.session.commit()
        result = {'code' : GOOD_CALL, 'message' : 'Device configuration updated'}
        return json.dumps(result)
    
    @staticmethod
    def getJsonConfig(c):
        data = {}
        data['device_mac'] = c.device_mac
        data['device_status'] = c.device_status
        data['nickname'] = c.nickname
        data['configuration'] = c.configuration
        return data

class Log(Resource):
    @jwt_required()
    def get(self, group_id):
        if UserInformation.isAdmin(Customers.query.filter_by(id=current_identity.id).first().group_id):
            device_id = Customers.query.filter_by(group_id=group_id).first().configuration.id
            logs = Logs.query.filter_by(device_id=device_id)
            logHistory = []
            for l in logs:
                logHistory.append(Log.getJsonLogs(l))
            result = {'status' : GOOD_CALL, 'data': logHistory}
        else:
            device_id = Customers.query.filter_by(id=current_identity.id).first().configuration.id
            logs = Logs.query.filter_by(device_id=device_id)
            logHistory = []
            for l in logs:
                logHistory.append(Log.getJsonLogs(l))
            result = {'status' : GOOD_CALL, 'data': logHistory}
        return json.dumps(result)

    @jwt_required()
    def post(self, group_id):
        data = request.get_json()
        # Check content of data
        if 'event_id' not in data or 'timestamp' not in data or 'device_mac' not in data:
            print('Event is missing some fields.')
            exit()

        try:
            datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
        except:
            print("Wrong datetime format in event.")
            exit()

        if not UserInformation.isAdmin(Customers.query.filter_by(id=current_identity.id).first().group_id):
            print("User is not enabled to insert logs")
            exit()

        device_id = Configuration.query.filter_by(device_mac=data['device_mac']).first().id
        if not device_id:
            print "Device mac not found"
            exit()
        
        newLog = Logs(device_id, datetime.now(), datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S.%f'), data['event_id'], data['event'])
        db.session.add(newLog)
        db.session.commit()
        print("Committed new log to the DB")
    
    @staticmethod
    def getJsonLogs(c):
        data = {}
        data['device_id'] = c.device_id
        data['timestamp_srv'] = str(c.timestamp_srv)
        data['timestamp_dev'] = str(c.timestamp_dev)
        data['event_id'] = c.event_id
        data['event'] = c.event
        return data

# Routes
api.add_resource(DeviceConfiguration, '/user/<group_id>/devices') # Devices
api.add_resource(UserInformation, '/user/<group_id>') # User info
api.add_resource(VerifyCredentials, '/user/verify') # Authentication
api.add_resource(Log, '/user/<group_id>/logs') # Logs




# Security
app.config['SECRET_KEY'] = db_password
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(days=30)
jwt = JWT(app, JWTAuthenticator.authenticate, JWTAuthenticator.identity)

if __name__ == '__main__':
    try:
       db.create_all()
    except Exception as e:
        print "Unable to connect to the DB: " + e
        exit()

    app.run(host='0.0.0.0', port='5002')
