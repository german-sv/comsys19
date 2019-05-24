from flask import Flask
from flask import Flask, flash, redirect, render_template, request, session, abort, url_for
import os, requests, json

app = Flask(__name__)
API_URI = "http://localhost:5002/"
API_TOKEN = ""

f=open("/home/ubuntu/masterPassword","r")
db_password = f.readline().rstrip("\n\r")
API_AUTH = {"username" : "admin", "password" : db_password}

@app.route('/')
def home():
	if not session.get('logged_in'):
		return render_template('login.html')
	else:
		return redirect(url_for('user'))

@app.route('/login', methods=['POST'])
def do_admin_login():
	response = requests.post(API_URI+"user/verify", data=json.dumps({'group_id': request.form['username'], 'group_psw': request.form['password']}), headers={"Authorization": "JWT " + API_TOKEN, 'Content-Type': 'application/json'})

	if json.loads(json.loads(response.text))['code'] == 200:
		session['logged_in'] = True
		session['group_id'] = request.form['username']
		return redirect(url_for('user'))
	else:
		renewToken()

	return home()

@app.route('/user', methods=['GET', 'POST'])
def user():
	error_message = None
	if 'logged_in' not in session or session['logged_in'] == False:
			return render_template('login.html')
	renewToken()
	if request.method == 'POST':
		group_data = {"group_id":session['group_id'], "group_psw_new":request.form['group_psw_new'], "group_psw":request.form['group_psw'], "group_info":request.form['group_info']}
		if len(group_data['group_psw_new']) > 0 and len(group_data['group_psw_new']) < 4:
			error_message = "New password must be at least 4 characters long!"
			return render_template('user.html', error_message=error_message, **group_data)

		response = requests.post(API_URI+"user/"+session['group_id'], data=json.dumps(group_data), headers={"Authorization": "JWT " + API_TOKEN, 'Content-Type': 'application/json'})

		return render_template('user.html', error_message=error_message, **group_data)

	else:
		response = requests.get(API_URI+"user/"+session['group_id'],
			headers={"Authorization": "JWT " + API_TOKEN})
		print response.text
                group_data=json.loads(json.loads(response.text))
		group_data['error_message'] = error_message
		return render_template('user.html', **group_data)

def renewToken():
	response = requests.post(API_URI+"auth", data=json.dumps(API_AUTH),
            headers={'Content-Type': 'application/json'})
        print response.text
	if not json.loads(response.text)['access_token']:
		print "Could not obtain the API_TOKEN!"
		exit()

	API_TOKEN = json.loads(response.text)['access_token']

if __name__ == "__main__":
	app.secret_key = os.urandom(12)
	
	app.run(debug=True, host='0.0.0.0', port=80)
