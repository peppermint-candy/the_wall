from flask import Flask, render_template, request, session, redirect, flash
# import the Connector function
from flask.ext.bcrypt import Bcrypt
from the_wall_mysqlconnection import MySQLConnector
import re
import time

app = Flask(__name__)
mysql = MySQLConnector(app, 'the_wall')
app.secret_key = "Secret"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]+$')
NAME = re.compile(r'[0,1,2,3,4,5,6,7,8,9]')
bcrypt = Bcrypt(app)
now = time.localtime(time.time())
# time.strftime("%a %b %d", now)

@app.route('/')
def index():
	return render_template('register.html')

@app.route('/register', methods=["POST"])
def process():

	if len(request.form['email']) < 1:
		flash("Email cannot be blank!")
		error = False
    # else if email doesn't match regular expression display an "invalid email address" message
	elif not EMAIL_REGEX.match(request.form['email']):
		flash("Invalid Email Address!")
		error = False
	else:
		error = True
	
	if len(request.form['pw']) < 8:
		flash("Password has to be longer than 8 characters")
		error = False
	elif request.form['pw'] != request.form['c_pw']:
		flash("Password and Confirm Password does not macth, Try again.")
		error = False
	else:
		error = True


	if len(request.form['first_name']) < 1:
		flash("First Name must have at least 2 characters")	
		error = False
	elif NAME.search(request.form['first_name']):
		flash("First Name cannot contain number(s)")
		error = False
	else:
		error = True

	if len(request.form['last_name']) < 1:
		flash("Last Name must have at least 2 characters")	
		error = False
	elif NAME.search(request.form['last_name']):
		flash("Last Name cannot contain number(s)")
		error = False
	else:
		error = True

	if error:
		return create(request.form)
	else:
		flash("please validate your input")
		return redirect('/')

# @app.route('/create')
def create(data):

	pw = data['pw']
	print pw
	pw_hash = bcrypt.generate_password_hash(pw)

	insert_query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :pw, NOW(), NOW())"

	query_data = { 'first_name': data['first_name'], 'last_name': data['last_name'], 'email': data['email'], 'pw': pw_hash }

	mysql.query_db(insert_query, query_data)
	return redirect('/login')

@app.route('/verify', methods=['POST'])
def logintab():

	if len(request.form['elogin']) < 1:
		flash("Login e-mail cannot be blank!")
		error = False
	elif not EMAIL_REGEX.match(request.form['elogin']):
		flash("Invalid Email Address!")
		error = False
	else:
		error = True

	if len(request.form['Lpw']) < 1:
		flash("password can't be empty")
		error = False
	else:
		error = True
	
	if error:
		print "user entering check input"
		return check(request.form)
	else:
		flash("try again")
		return redirect('/login')

def check(data):
	print "checking input with DB"
	user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
	query_data = {'email' : data['elogin']}
	user = mysql.query_db(user_query, query_data)
	if bcrypt.check_password_hash(user[0]['password'], data['Lpw']):
		session['id_user'] = user[0]['id']
		session['name_user'] = user[0]['first_name']
		print "user is logged in"
		return redirect('/wall')
	else:
		flash("Wrong password, please try again")
		return	redirect('/login')

@app.route('/login')
def test():
	print "user entering login page"
	return render_template('login_page.html')

@app.route('/pass')
def login():
	print "user successfully registered"
	return redirect('/login')

@app.route('/wall')
def wall():

	query_msg = "SELECT messages.id as m_id, users.first_name, messages.created_at, messages.message FROM messages JOIN users ON users.id = messages.users_id"
	posts = mysql.query_db(query_msg)

	query_cmnt = "SELECT messages.id as m_id, users.first_name, comments.messages_id, comments.created_at, comments.comment FROM comments JOIN users ON users.id = comments.users_id JOIN messages ON messages.id = comments.messages_id"
	cmnts = mysql.query_db(query_cmnt)
	return render_template('logged_in.html' ,all_posts = posts, all_cmnts = cmnts)

@app.route('/msg' , methods =['POST'])
def msg():
	print " in message"
	if request.form['msg'] != "":
		insert(request.form)
	else:
		print "post is empty"

	return redirect('/wall')

def insert(data):

	insert_query = "INSERT INTO messages (message, users_id, created_at, updated_at) VALUES (:message, :users_id, NOW(), NOW())"
	query_data = { 'message': data['msg'] , 'users_id': session['id_user'] }
	messages = mysql.query_db(insert_query, query_data)

	return redirect('/wall')

@app.route('/comment', methods=['POST'])
def comment():
	print "in comment"
	if request.form['comment'] != "":
		post_comment(request.form)
	else:
		print "comment is empty"
	return redirect('/wall')

def post_comment(data):
	insert_query = "INSERT INTO comments (comment, users_id, messages_id, created_at, updated_at) VALUES (:comment, :users_id, :messages_id, NOW(), NOW())"
	query_data = { 'comment': data['comment'] , 'users_id': session['id_user'] ,'messages_id': data['comment_post']}
	comments = mysql.query_db(insert_query, query_data)
	return redirect('/wall')
		
# @app.route('/logoff')
# def logof():
# 	session.clear()
# 	return redirect('/login')

app.run(debug=True)


#comment out 
#SELECT messages.id as m_id, comments.comment FROM comments JOIN users ON users.id = comments.users_id JOIN messages ON messages.id = comments.messages_id