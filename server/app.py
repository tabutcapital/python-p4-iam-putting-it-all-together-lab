from flask import Flask, request, jsonify, session
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Recipe  # Ensure this imports the db instance
from werkzeug.exceptions import UnprocessableEntity

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'  # Session secret key
migrate = Migrate(app, db)
db.init_app(app)  # Ensuring that db is initialized with the app

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()  # Ensure the request data is in JSON format
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"message": "Missing username or password"}), 422

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"message": "Username already exists"}), 422

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id  # Ensure session is set after user creation

        return jsonify({"message": "User created successfully"}), 201

    except Exception as e:
        db.session.rollback()  # Rollback in case of an error
        print(f"Error during signup: {e}")  # Log the error for debugging
        return jsonify({"message": str(e)}), 500



@app.route('/check_session', methods=['GET'])
def check_session():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"message": "Unauthorized"}), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        "image_url": user.image_url,
        "bio": user.bio
    })


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 422

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401


@app.route('/logout', methods=['POST'])
def logout():
    if 'user_id' not in session:
        return jsonify({"message": "Unauthorized"}), 401
    session.pop('user_id', None)
    return jsonify({"message": "Logged out successfully"}), 204


@app.route('/recipes', methods=['GET'])
def get_recipes():
    if 'user_id' not in session:
        return jsonify({"message": "Unauthorized"}), 401
    recipes = Recipe.query.filter_by(user_id=session['user_id']).all()
    return jsonify([{
        "id": recipe.id,
        "title": recipe.title,
        "instructions": recipe.instructions,
        "minutes_to_complete": recipe.minutes_to_complete,
    } for recipe in recipes])


@app.route('/recipes', methods=['POST'])
def create_recipe():
    if 'user_id' not in session:
        return jsonify({"message": "Unauthorized"}), 401
    data = request.get_json()
    title = data.get('title')
    instructions = data.get('instructions')
    minutes_to_complete = data.get('minutes_to_complete')

    if not title or not instructions or minutes_to_complete is None:
        return jsonify({"message": "Invalid recipe data"}), 422

    new_recipe = Recipe(
        title=title,
        instructions=instructions,
        minutes_to_complete=minutes_to_complete,
        user_id=session['user_id']
    )
    db.session.add(new_recipe)
    db.session.commit()

    return jsonify({"message": "Recipe created successfully"}), 201


if __name__ == '__main__':
    app.run(port=5555, debug=True)
