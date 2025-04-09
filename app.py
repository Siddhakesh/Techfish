from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
CORS(app)

# MongoDB Atlas connection
MONGO_URI = "mongodb+srv://techfishuser:MySecurePass123@cluster0.kekjcdy.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI)
db = client['techfish']
users_collection = db['users']

# Helper: Hash a password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Helper: Check hashed password
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Route for Signup
@app.route('/submit', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    if users_collection.find_one({'username': username}):
        return jsonify({"message": "Username already exists!"}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({"message": "Email already registered!"}), 400

    hashed_pw = hash_password(data['password'])

    user_data = {
        "name": data['name'],
        "username": username,
        "email": email,
        "password": hashed_pw
    }

    users_collection.insert_one(user_data)
    return jsonify({"message": "Signup successful!"}), 200

# Route for Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = users_collection.find_one({"username": username})
    if user and check_password(password, user['password']):
        return jsonify({"message": "Login successful!"}), 200
    else:
        return jsonify({"message": "Invalid username or password!"}), 401

if __name__ == '__main__':
    app.run(debug=True)
