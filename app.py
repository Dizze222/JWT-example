from datetime import timedelta

from flask_jwt_extended import create_access_token, create_refresh_token, JWTManager
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask import jsonify, Flask, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'my-super-secret-key'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)
jwt = JWTManager(app)
db = SQLAlchemy(app)


class AuthModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phoneNumber = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String, nullable=False)
    secondName = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)


class ProfileModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    secondName = db.Column(db.String, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    image = db.Column(db.String, nullable=False)
    bio = db.Column(db.String, nullable=False)
    idOfUser = db.Column(db.Integer, nullable=False)


@app.route('/register', methods=['POST'])
def register_user():
    try:
        phoneNumber = int(request.form['phoneNumber'])
        name = str(request.form['name'])
        secondName = str(request.form['secondName'])
        password = str(request.form['password'])
        print(phoneNumber, name, secondName, password, "   /register")
        model = AuthModel.query.order_by(AuthModel.date).all()

        for i in model:
            print(i.phoneNumber)
            if phoneNumber == int(i.phoneNumber):
                return jsonify([{'accessToken': None, 'refreshToken': None, 'successRegister': False}])
        accessToken = create_access_token(identity=phoneNumber, expires_delta=timedelta(minutes=30), fresh=True)
        refreshToken = create_refresh_token(identity=phoneNumber, expires_delta=timedelta(days=30))
        modelOfRegister = AuthModel(phoneNumber=phoneNumber, name=name, secondName=secondName, password=password)
        modelOfUserProfile = ProfileModel(name=name, secondName=secondName, image="empty", idOfUser=phoneNumber,
                                          bio="no bio")
        db.session.add(modelOfRegister)
        db.session.add(modelOfUserProfile)
        db.session.commit()
        return jsonify([{'accessToken': accessToken, 'refreshToken': refreshToken, 'successRegister': True}])
    except Exception as error:
        print(error)
        return error


# Login
@app.route('/authentication', methods=['POST'])
def login_user():
    try:
        phoneNumber = int(request.form['phoneNumber'])
        password = str(request.form['password'])
        model = AuthModel.query.order_by(AuthModel.date).all()
        print(phoneNumber, password, "   /authentication")
        for i in model:
            if password == str(i.password) and phoneNumber == int(i.phoneNumber):
                print("point 1")
                accessToken = create_access_token(identity=phoneNumber, expires_delta=timedelta(minutes=5), fresh=True)
                refreshToken = create_refresh_token(identity=phoneNumber, expires_delta=timedelta(days=30))
                print("return true")
                return jsonify([{'accessToken': accessToken, 'refreshToken': refreshToken, 'success': True}])
        else:
            print("return false")
            return jsonify([{'accessToken': None, 'refreshToken': None, 'success': False}])
    except Exception as error:
        print(error)
        return "some exeption"


#GET
@app.route('/token/refresh')
@jwt_required(refresh=True)
def refresh_token():
    identity = get_jwt_identity()
    accessToken = create_access_token(identity=identity)
    refreshToken = create_refresh_token(identity=identity)
    print(accessToken, refreshToken)
    return jsonify({'accessToken': accessToken, 'refreshToken': refreshToken, 'success': True})


@app.route('/endpoint', methods=['GET'])
@jwt_required()
def endpoint():
    return jsonify([{
        'message': "Token is valid"
    }])


if __name__ == '__main__':
    app.run()
