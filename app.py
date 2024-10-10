from flask import Flask, request, jsonify
from user import User, Dieta
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/controle-de-dieta'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
        return User.query.get(user_id)

@app.route('/login', methods=['POST'])
def login():
        data = request.json
        username = data.get("username")
        password = data.get("password")

        if username and password:
                user = User.query.filter_by(username=username).first()

                if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
                        login_user(user)
                        print(current_user.is_authenticated)
                        return jsonify({"message": "autenticação realizada com sucesso."})

        return jsonify({"message": "Credenciais invalidas."}), 400

@app.route('/logout', methods=['GET'])
@login_required
def logout():
        logout_user()
        return jsonify({"message": "Logout realizado com sucesso."})

@app.route('/create-user', methods=['POST'])
def create_user():
        data = request.json
        username = data.get("username")
        password = data.get("password")

        if username and password:
                hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
                user = User(username=username, password=hashed_password, role='user')
                db.session.add(user)
                db.session.commit()
                return jsonify({"message": "Usuário cadastrado com sucesso."})

        return jsonify({"message":"Dados invalidos."}), 400

@app.route('/user/<int:id_user>', methods=['GET'])
@login_required
def read_user(id_user):
        user = User.query.get(id_user)

        if user:
                return {"username": user.username}
        
        return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/refeicoes', methods=['GET'])
@login_required
def get_meals():
    dietas = Dieta.query.filter_by(user_id=current_user.id).all()
    if dietas:
        return jsonify([{'id': dieta.id, 'nome_refeicao': dieta.nome_refeicao} for dieta in dietas])
    return jsonify({"message": "Nenhuma refeição encontrada"}), 404
@app.route('/refeicao', methods=['POST'])
@login_required
def add_meal():
        nova_dieta = request.get_json()
        refeicao = Dieta(
                nome_refeicao=nova_dieta.get('nome_refeicao'),
                user_id=current_user.id
        )
        db.session.add(refeicao)
        db.session.commit()
        print(current_user)
        print(current_user.id) 
        return jsonify({"message": "Refeição adicionada com sucesso."})
        
@app.route('/refeicao/<int:meal_id>', methods=['PUT'])
@login_required
def update_meal(meal_id):
    dieta = Dieta.query.filter_by(id=meal_id, user_id=current_user.id).first()
    if not dieta:
        return jsonify({"message": "Refeição não encontrada ou não autorizada"}), 404
    
    nova_refeicao = request.get_json().get('nome_refeicao')
    if nova_refeicao:
        dieta.nome_refeicao = nova_refeicao
        db.session.commit()
        return jsonify({"message": "Refeição atualizada com sucesso"})
    
    return jsonify({"message": "Dados inválidos"}), 400
@app.route('/refeicao/<int:meal_id>', methods=['DELETE'])
@login_required
def delete_meal(meal_id):
    dieta = Dieta.query.filter_by(id=meal_id, user_id=current_user.id).first()
    if not dieta:
        return jsonify({"message": "Refeição não encontrada ou não autorizada"}), 404
    
    db.session.delete(dieta)
    db.session.commit()
    return jsonify({"message": "Refeição removida com sucesso"})

@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
        data = request.json
        user = User.query.get(id_user)
        if id_user != current_user.id and current_user.role == "user":
                return jsonify({"message": "Operação não permitida"}), 403
        
        if user and data.get("password"):
                user.password = data.get("password")
                db.session.commit()

                return jsonify({"message": f"Usuário {id_user} atualizado."})
        
        return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
        user = User.query.get(id_user)

        if current_user.role != 'admin':
                return jsonify({"message": "operação não permitida."})

        if id_user == current_user.id:
                return jsonify({"message": "Deleção não permitida."}), 403

        if user:
                db.session.delete(user)
                db.session.commit()
                return jsonify({"message": f"Usuário {id_user} deletado com sucesso."})
        
        return jsonify({"message": "Usuário não encontrado"}), 404
     

if __name__ == '__main__':
        app.run(debug=True)