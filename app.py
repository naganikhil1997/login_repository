from flask import Flask, request, jsonify
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from bson import ObjectId
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt, get_jwt_identity
from flask_cors import CORS

app = Flask(__name__)
CORS(app) 

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client.flask_auth
users_collection = db.users
blacklist = set()  # Set to store blacklisted JWT tokens

bcrypt = Bcrypt(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'supersecretkey'  # Change this to a secure key
jwt = JWTManager(app)

# Registration route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if users_collection.find_one({"email": email}):
        return jsonify({"message": "User already exists"}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = {
        "username": username,
        "email": email,
        "password": hashed_password
    }

    users_collection.insert_one(new_user)
    return jsonify({"message": "User registered successfully"}), 201


# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    user = users_collection.find_one({"email": email})

    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=str(user['_id']))
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Invalid email or password"}), 401


# Logout route
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]  # JWT unique identifier
    blacklist.add(jti)  # Blacklist the token
    return jsonify({"message": "Logged out successfully"}), 200


# Route to get user details (Protected Route)
@app.route('/user/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    if get_jwt_identity() != user_id:
        return jsonify({"message": "Unauthorized access"}), 403

    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user:
        user_data = {
            "username": user["username"],
            "email": user["email"]
        }
        return jsonify(user_data), 200
    else:
        return jsonify({"message": "User not found"}), 404


# Check if a token is in the blacklist
@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    return jwt_payload["jti"] in blacklist


if __name__ == '__main__':
    app.run(debug=True, port=8080)