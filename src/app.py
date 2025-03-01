import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Set the template folder relative to this file's location
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
app = Flask(__name__, template_folder=template_dir)

app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default-insecure-key')

# Configure the SQLite database (stored in the mounted /data directory)
db_path = os.path.join("/data", "app.db")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ----------------------
# Models
# ----------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    entries = db.relationship('Entry', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)  # Allowed: 'needs', 'wants', 'savings'
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------------
# Utility Functions
# ----------------------
def calculate_score(user):
    """Score calculation: needs +1 per dollar, wants +2 per dollar, savings -2 per dollar."""
    score = 0
    for entry in user.entries:
        if entry.category == 'needs':
            score += entry.amount * 1
        elif entry.category == 'wants':
            score += entry.amount * 2
        elif entry.category == 'savings':
            score -= entry.amount * 2
    return score

# ----------------------
# Routes
# ----------------------
@app.route('/')
@login_required
def index():
    entries = Entry.query.filter_by(user_id=current_user.id).order_by(Entry.timestamp.desc()).all()
    totals = {'needs': 0, 'wants': 0, 'savings': 0}
    for entry in entries:
        if entry.category in totals:
            totals[entry.category] += entry.amount
    score = calculate_score(current_user)
    return render_template('index.html', entries=entries, totals=totals, score=score)

@app.route('/add', methods=['POST'])
@login_required
def add_entry():
    category = request.form.get('category')
    amount = request.form.get('amount')
    description = request.form.get('description')
    try:
        amount = float(amount)
    except ValueError:
        flash("Invalid amount", "danger")
        return redirect(url_for('index'))
    if category not in ['needs', 'wants', 'savings']:
        flash("Invalid category", "danger")
        return redirect(url_for('index'))
    entry = Entry(category=category, amount=amount, description=description, user_id=current_user.id)
    db.session.add(entry)
    db.session.commit()
    flash("Entry added", "success")
    return redirect(url_for('index'))

@app.route('/leaderboard')
@login_required
def leaderboard():
    users = User.query.all()
    leaderboard = []
    for user in users:
        leaderboard.append({
            'username': user.username,
            'score': calculate_score(user)
        })
    leaderboard = sorted(leaderboard, key=lambda x: x['score'])
    return render_template('leaderboard.html', leaderboard=leaderboard)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful, please login", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully", "success")
            return redirect(url_for('index'))
        flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out", "success")
    return redirect(url_for('login'))

# ----------------------
# Database Initialization
# ----------------------
@app.before_request
def create_tables():
    app.before_request_funcs[None].remove(create_tables)
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
