import json
from flask import Flask, request, jsonify, abort

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy import TypeDecorator, VARCHAR

from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth

from decouple import config


app = Flask(__name__)
auth = HTTPBasicAuth()

user_auth = {
    config('USER_LOGIN'): generate_password_hash(config('USER_PASSWORD'))
}


@auth.verify_password
def verify_password(username, password):
    if username in user_auth and \
            check_password_hash(user_auth.get(username), password):
        return username


engine = create_engine(config('URL_DATABASE'))
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Session = sessionmaker(bind=engine)
session = Session()

Base = declarative_base()
Base.query = db_session.query_property()


class JSONEncodedDict(TypeDecorator):
    impl = VARCHAR

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value, ensure_ascii=False)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


class Message(Base):
    __tablename__ = 'messages'
    id = Column(Integer, primary_key=True)
    nome_usuario = Column(String(2042))
    id_profile_linkedin = Column(String(2042), unique=True)
    message = Column(JSONEncodedDict())

    def __init__(self, nome_usuario, id_profile_linkedin, message):
        self.nome_usuario = nome_usuario
        self.id_profile_linkedin = id_profile_linkedin
        self.message = message


Base.metadata.create_all(engine)


@app.route('/add-message', methods=['POST'])
@auth.login_required
def add_message():
    nome_usuario = request.json['nome_usuario']
    id_profile_linkedin = request.json['id_profile_linkedin']
    message = request.json['message']

    usuario_existente = Message.query.filter_by(id_profile_linkedin=id_profile_linkedin).first()

    new_usuario = None
    if usuario_existente is not None:
        usuario_existente.message.extend(message)
        flag_modified(usuario_existente, "message")
    else:
        new_usuario = Message(nome_usuario, id_profile_linkedin, message)
        db_session.add(new_usuario)

    db_session.commit()

    if usuario_existente is not None:
        return {'status': 'message updated'}
    else:
        return {'status': 'new user created', 'id': new_usuario.id}


@app.route('/message', methods=['GET'])
@auth.login_required
def get_message():
    id_profile_linkedin = request.args.get('id_profile_linkedin')
    usuario = Message.query.filter_by(id_profile_linkedin=id_profile_linkedin).first()
    if usuario is None:
        abort(404)

    return jsonify({c.name: getattr(usuario, c.name) for c in Message.__table__.columns}, None)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(config('PORT')))
