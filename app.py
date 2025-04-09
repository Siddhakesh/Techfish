from flask import Flask, request, jsonify , render_template
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import os


app = Flask(__name__, template_folder='.')
CORS(app)
# Connect to MongoDB using the provided connection string
client = pymongo.MongoClient(os.environ["MONGO_URI"])
db = client.get_database("FS_project")
users_collection = db.get_collection("Data1")
print("Connected to MongoDB")
print(users_collection)

@app.route('/')
def home():
    return render_template('landing.html')
@app.route('/<page>')
def render_any_html(page):
    return render_template(f"{page}")  # Renders HTML files dynamically
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"message": "No input data provided"}), 400

    name = data.get('name')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    print(name, username, email, password)
    # Basic validation
    if not all([name, username, email, password]):
        return jsonify({"message": "Missing fields"}), 400
    if len(password) < 6:
        return jsonify({"message": "Password must be at least 6 characters long"}), 400

    # Check for duplicate user
    if users_collection.find_one({"email": email}):
        return jsonify({"message": "User with that email already exists"}), 400
    if users_collection.find_one({"username": username}):
        return jsonify({"message": "Username already taken"}), 400

    # Hash the password and prepare the document
    hashed_password = generate_password_hash(password)
    user_data = {
        "name": name,
        "username": username,
        "email": email,
        "password": hashed_password
    }

    try:
        users_collection.insert_one(user_data)
        print("User registered successfully")
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        print("An error occurred while registering the user:", str(e))
        return jsonify({"message": "An error occurred while registering the user"}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No data provided"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400

    # Find the user by username
    user = users_collection.find_one({"username": username})
    if not user:
        return jsonify({"success": False, "message": "Invalid username or password"}), 401

    # Validate the provided password against the hashed password stored in MongoDB
    if check_password_hash(user["password"], password):
        return jsonify({"success": True, "message": "Login successful"}), 200
    else:
        return jsonify({"success": False, "message": "Invalid username or password"}), 401


if __name__ == '__main__':
    app.run(debug=True , port=5500, host='127.0.0.1')
