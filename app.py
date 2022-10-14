from flask import Flask,request,redirect,jsonify,make_response
import uuid
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "thisissecret"

db = SQLAlchemy(app)

@app.before_first_request
def create_tables():
    db.create_all()

class User(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    public_id = db.Column(db.String(50),unique=True)
    name = db.Column(db.String(15),unique=True)
    email = db.Column(db.String(50),unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class ToDo(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    text = db.Column(db.String(100))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id = data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid !!'}), 401

        return  f(current_user, *args, **kwargs)
  
    return decorated


@app.route('/user',methods = ['GET'])

def get_all_users():

    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'message':output})


@app.route('/user/<public_id>',methods = ['GET'])

def get_one_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message':"No user Found"})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user':user_data})

@app.route('/user',methods = ['POST'])
def create_user():

    data = request.get_json()
    
    hashed_password  = generate_password_hash(data['password'],method='sha256')
    new_user = User(public_id=str(uuid.uuid4()),name=data['name'],email =data['email'],password=hashed_password,admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message':'New User Created'})

@app.route('/user/<public_id>',methods = ['PUT'])
def promote_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message':"No user Found"})

    user.admin = True
    db.session.commit()

    return jsonify({'message':'User has been promoted'})

@app.route('/user/<public_id>',methods = ['DELETE'])
def delete_user(public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message':"No user Found"})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message':"User Deleted Sucessfully"})



@app.route('/login',methods=['POST'])
def login():
    auth = request.authorization
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return make_response('Could not verify',401,{'WWW-Authenticate' : 'Basic realm ="Login required !!"'})
  
    user = User.query.filter_by(email = auth.get('username')).first()
  
    if not user:
        return make_response('Could not verify',401,{'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'})
  
    if check_password_hash(user.password, auth.get('password')):
        token = jwt.encode({'public_id':user.public_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=15)},app.config['SECRET_KEY'])
        return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)

    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )


@app.route('/todo',methods=['GET'])
@token_required
def get_all_todos(current_user,):
    todos = ToDo.query.filter_by(user_id=current_user.id).all()
    output = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)
    return jsonify({"todos":output})


@app.route('/todo/<todo_id>',methods=['GET'])
@token_required
def get_one_todo(current_user,todo_id):
    todo = ToDo.query.filter_by(id=todo_id,user_id=current_user.id).first()

    if not todo:
        return jsonify({'message':'No Todo Found'})

    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete


    return jsonify(todo_data)

@app.route('/todo',methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()
    print(data)
    new_todo = ToDo(text=data['text'],complete=False,user_id=current_user)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'message':'ToDo created'})

@app.route('/todo/<todo_id>',methods=['PUT'])
@token_required
def complete_todo(current_user,todo_id):
    todo = ToDo.query.filter_by(id=todo_id,user_id=current_user.id).first()

    if not todo:
        return jsonify({'message':'No Todo Found'})

    todo.complete = True
    db.session.commit()
    return jsonify({'message':"ToDo task Completed"})

@app.route('/todo/<todo_id>',methods=['DELETE'])
@token_required
def delete_todo(current_user,todo_id):
    todo = ToDo.query.filter_by(id=todo_id,user_id=current_user.id).first()

    if not todo:
        return jsonify({'message':'No Todo Found'})

    db.session.delete(todo)
    db.session.commit()
    return jsonify({'message':"ToDo task deleted"})


if __name__ == "__main__":
    app.run(debug=True)