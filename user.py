from flask_login import UserMixin
from database import db

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    dietas = db.relationship('Dieta', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Dieta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome_refeicao = db.Column(db.String(100), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Dieta {self.nome_refeicao}>'