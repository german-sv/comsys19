import fdb
import json
from flask_jwt import JWT, jwt_required, current_identity
from werkzeug.security import safe_str_cmp
import firebirdsql
from flask_sqlalchemy import SQLAlchemy
import random
import string

def randomString(stringLength=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

db_host = "localhost"
userName = "sysdba"
f=open("/home/ubuntu/masterPassword","r")
db_password = f.readline().rstrip("\n\r")
db_name = "/home/ubuntu/DB/pl19.fdb"
con = firebirdsql.connect(host=db_host, database=db_name, user=userName, password=db_password)
cur = con.cursor()

cur.execute("delete from customers")
cur.execute("delete from configuration")
con.commit()

fp = open(".credentials", "w")
for g in xrange(1, 50):
	group_id = "PL19-%02d" % (g)
	group_psw = group_id+"-"+randomString(2)
	insertStatement = "insert into customers (group_id, group_psw, group_info) values (?,?,?)"
	data = (group_id, group_psw, "{}")
	cur.execute(insertStatement, data)
	fp.write(group_id + "\t" + group_psw + "\n")
insertStatement = "insert into customers (group_id, group_psw, group_info) values (?,?,?)"
data = ("admin", db_password, "{}")
cur.execute(insertStatement, data)
data = ("german", db_password, "{}")
cur.execute(insertStatement, data)

con.commit()
fp.close()

for g in xrange(1, 50):
	group_id = "PL19-%02d" % (g)

	customer_id = cur.execute("select id from customers where group_id like '%s'" % group_id).fetchone()[0]
	device_mac = "00:00:00:00:00:"+"%02d" % (g)
	device_status = random.randint(0,2)
	nickname = "RP-"+group_id
	configuration = {}
	configuration["DEVICE"] = "RP v3b"
	configuration["NUM_SENSORS"] = 7
	configuration["WIFI_SSID"] = "Home-Wifi"
	configuration["OWNER"] = nickname
	print customer_id
	insertStatement = "insert into configuration (customer_id, device_mac, device_status, nickname, configuration) values (?,?,?,?,?)"
	data = (customer_id, device_mac, device_status, nickname, json.dumps(configuration))
	cur.execute(insertStatement, data)

insertStatement = "insert into configuration (customer_id, device_mac, device_status, nickname, configuration) values (?,?,?,?,?)"
customer_id = cur.execute("select id from customers where group_id = 'admin'").fetchone()[0]
data = (customer_id, "00:00:00:00:00:00", 0, 'server', ' ')
cur.execute(insertStatement, data)
con.commit()
con.close()