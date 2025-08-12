# --- Imports ---
import os, json, logging, time, uuid, secrets
from flask import Flask, Response, request, session, jsonify, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import stripe
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_mail import Mail, Message
from flask_talisman import Talisman
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, or_, func
from sqlalchemy.engine import Engine
from flask_socketio import SocketIO, emit, join_room, leave_room
# ==============================================================================
# --- 1. INITIAL CONFIGURATION & SETUP ---
# ==============================================================================
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# --- Security Check for Essential Environment Variables ---
REQUIRED_KEYS = [
    'SECRET_KEY', 'SECURITY_PASSWORD_SALT', 'SECRET_TEACHER_KEY',
    'STRIPE_WEBHOOK_SECRET', 'STRIPE_SECRET_KEY', 'STRIPE_PUBLIC_KEY', 'STRIPE_STUDENT_PRICE_ID', 'STRIPE_STUDENT_PRO_PRICE_ID',
    'MAIL_SERVER', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD', 'MAIL_SENDER'
]
for key in REQUIRED_KEYS:
    if not os.environ.get(key):
        logging.critical(f"CRITICAL ERROR: Environment variable '{key}' is not set.")
        exit(f"Error: Missing required environment variable '{key}'.")
# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# --- Security: Content Security Policy (CSP) ---
csp = {
    'default-src': "'self'",
    'script-src': ["'self'", "https://js.stripe.com", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com", "'unsafe-inline'"],
    'style-src': ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
    'font-src': ["'self'", "https://fonts.gstatic.com"],
    'img-src': ["'self'", "https://*", "data:"],
}
Talisman(app, content_security_policy=csp)
# --- Site & API Configuration ---
SITE_CONFIG = {
    "STRIPE_SECRET_KEY": os.environ.get('STRIPE_SECRET_KEY'),
    "STRIPE_PUBLIC_KEY": os.environ.get('STRIPE_PUBLIC_KEY'),
    "STRIPE_STUDENT_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRICE_ID'),
    "STRIPE_STUDENT_PRO_PRICE_ID": os.environ.get('STRIPE_STUDENT_PRO_PRICE_ID'),
    "YOUR_DOMAIN": os.environ.get('YOUR_DOMAIN', 'http://localhost:5000'),
    "SECRET_TEACHER_KEY": os.environ.get('SECRET_TEACHER_KEY'),
    "STRIPE_WEBHOOK_SECRET": os.environ.get('STRIPE_WEBHOOK_SECRET'),
}
# --- Service Initializations (Stripe, Mail, DB, SocketIO) ---
stripe.api_key = SITE_CONFIG["STRIPE_SECRET_KEY"]
password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_SENDER')
mail = Mail(app)
# ==============================================================================
# --- 2. DATABASE MODELS (SQLALCHEMY) ---
# ==============================================================================
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()
student_class_association = db.Table('student_class_association',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('class_id', db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), primary_key=True)
)
class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='student')
    plan = db.Column(db.String(50), nullable=False, default='free')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_bio = db.Column(db.Text, default='')
    profile_avatar = db.Column(db.String(200), default='')
    stripe_customer_id = db.Column(db.String(255), unique=True, nullable=True)
    stripe_subscription_id = db.Column(db.String(255), unique=True, nullable=True)
    taught_classes = db.relationship('Class', back_populates='teacher', lazy=True, foreign_keys='Class.teacher_id', cascade="all, delete-orphan")
    enrolled_classes = db.relationship('Class', secondary=student_class_association, back_populates='students', lazy='dynamic')
    submissions = db.relationship('AssignmentSubmission', back_populates='student', lazy=True, cascade="all, delete-orphan")
    notifications = db.relationship('Notification', back_populates='user', lazy=True, cascade="all, delete-orphan")
    quiz_attempts = db.relationship('QuizAttempt', back_populates='student', lazy=True, cascade="all, delete-orphan")
    def to_dict(self):
        return {
            "id": self.id, "username": self.username, "email": self.email, "role": self.role, "plan": self.plan,
            "profile": {"bio": self.profile_bio, "avatar": self.profile_avatar},
            "classes": [c.id for c in self.enrolled_classes] if self.role == 'student' else [c.id for c in self.taught_classes],
            "created_at": self.created_at.isoformat(), "has_subscription": bool(self.stripe_subscription_id)
        }
class Class(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(8), unique=True, nullable=False)
    teacher_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    teacher = db.relationship('User', back_populates='taught_classes', foreign_keys=[teacher_id])
    students = db.relationship('User', secondary=student_class_association, back_populates='enrolled_classes', lazy='dynamic')
    messages = db.relationship('Message', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")
    assignments = db.relationship('Assignment', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")
    quizzes = db.relationship('Quiz', back_populates='class_obj', lazy=True, cascade="all, delete-orphan")
    def to_dict(self, include_students=False, student_count=False):
        data = { "id": self.id, "name": self.name, "code": self.code, "teacher_id": self.teacher_id, "teacher_name": self.teacher.username if self.teacher else "N/A" }
        if include_students: data['students'] = [s.to_dict() for s in self.students]
        if student_count: data['student_count'] = self.students.count()
        return data
class Message(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    class_obj = db.relationship('Class', back_populates='messages')
    sender = db.relationship('User')
    def to_dict(self):
        return { "id": self.id, "class_id": self.class_id, "sender_id": self.sender_id, "sender_name": self.sender.username if self.sender else "AI System", "sender_avatar": self.sender.profile_avatar if self.sender else None, "content": self.content, "timestamp": self.timestamp.isoformat() }
class Assignment(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    class_obj = db.relationship('Class', back_populates='assignments')
    submissions = db.relationship('AssignmentSubmission', back_populates='assignment', lazy='dynamic', cascade="all, delete-orphan")
    def to_dict(self, student_id=None):
        data = { "id": self.id, "title": self.title, "description": self.description, "due_date": self.due_date.isoformat(), "class_id": self.class_id, "submission_count": self.submissions.count() }
        if student_id:
            submission = self.submissions.filter_by(student_id=student_id).first()
            data['student_submission'] = submission.to_dict() if submission else None
        return data
class AssignmentSubmission(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    assignment_id = db.Column(db.String(36), db.ForeignKey('assignment.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    grade = db.Column(db.String(10), nullable=True)
    feedback = db.Column(db.Text, nullable=True)
    assignment = db.relationship('Assignment', back_populates='submissions')
    student = db.relationship('User', back_populates='submissions')
    def to_dict(self):
        return { "id": self.id, "assignment_id": self.assignment_id, "student_id": self.student_id, "student_name": self.student.username, "content": self.content, "submitted_at": self.submitted_at.isoformat(), "grade": self.grade, "feedback": self.feedback }
class Quiz(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    time_limit = db.Column(db.Integer, nullable=False) # in minutes
    class_id = db.Column(db.String(36), db.ForeignKey('class.id', ondelete='CASCADE'), nullable=False)
    class_obj = db.relationship('Class', back_populates='quizzes')
    questions = db.relationship('Question', back_populates='quiz', lazy='dynamic', cascade="all, delete-orphan")
    attempts = db.relationship('QuizAttempt', back_populates='quiz', lazy='dynamic', cascade="all, delete-orphan")
    def to_dict(self, student_id=None):
        data = { "id": self.id, "title": self.title, "description": self.description, "time_limit": self.time_limit, "class_id": self.class_id, "question_count": self.questions.count() }
        if student_id:
            attempt = self.attempts.filter_by(student_id=student_id).first()
            data['student_attempt'] = attempt.to_dict() if attempt else None
        return data
class Question(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    quiz_id = db.Column(db.String(36), db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(50), nullable=False) # 'multiple_choice', 'short_answer'
    order = db.Column(db.Integer, nullable=False)
    quiz = db.relationship('Quiz', back_populates='questions')
    choices = db.relationship('Choice', back_populates='question', lazy='dynamic', cascade="all, delete-orphan")
    def to_dict(self, include_correct=False):
        data = { "id": self.id, "text": self.text, "question_type": self.question_type, "order": self.order, "choices": [c.to_dict(include_correct) for c in self.choices] }
        return data
class Choice(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    question_id = db.Column(db.String(36), db.ForeignKey('question.id', ondelete='CASCADE'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    is_correct = db.Column(db.Boolean, default=False, nullable=False)
    question = db.relationship('Question', back_populates='choices')
    def to_dict(self, include_correct=False):
        data = { "id": self.id, "text": self.text }
        if include_correct: data['is_correct'] = self.is_correct
        return data
class QuizAttempt(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    quiz_id = db.Column(db.String(36), db.ForeignKey('quiz.id', ondelete='CASCADE'), nullable=False)
    student_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    score = db.Column(db.Float, nullable=True)
    quiz = db.relationship('Quiz', back_populates='attempts')
    student = db.relationship('User', back_populates='quiz_attempts')
    answers = db.relationship('Answer', back_populates='attempt', lazy='dynamic', cascade="all, delete-orphan")
    def to_dict(self):
        return { "id": self.id, "quiz_id": self.quiz_id, "student_id": self.student_id, "student_name": self.student.username, "start_time": self.start_time.isoformat(), "end_time": self.end_time.isoformat() if self.end_time else None, "score": self.score }
class Answer(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    attempt_id = db.Column(db.String(36), db.ForeignKey('quiz_attempt.id', ondelete='CASCADE'), nullable=False)
    question_id = db.Column(db.String(36), db.ForeignKey('question.id', ondelete='CASCADE'), nullable=False)
    choice_id = db.Column(db.String(36), db.ForeignKey('choice.id'), nullable=True) # For multiple choice
    answer_text = db.Column(db.Text, nullable=True) # For short answer
    is_correct = db.Column(db.Boolean, nullable=True)
    attempt = db.relationship('QuizAttempt', back_populates='answers')
    question = db.relationship('Question')
    choice = db.relationship('Choice')
    def to_dict(self):
        return { "id": self.id, "question_id": self.question_id, "choice_id": self.choice_id, "answer_text": self.answer_text, "is_correct": self.is_correct }
class Notification(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    url = db.Column(db.String(255), nullable=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='notifications')
    def to_dict(self):
        return { "id": self.id, "content": self.content, "url": self.url, "is_read": self.is_read, "timestamp": self.timestamp.isoformat() }
class SiteSettings(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(500))
# ==============================================================================
# --- 3. USER & SESSION MANAGEMENT ---
# ==============================================================================
login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/'): return jsonify({"error": "Login required.", "logged_in": False}), 401
    return redirect(url_for('index'))
@login_manager.user_loader
def load_user(user_id): return User.query.get(user_id)
# ==============================================================================
# --- 4. DECORATORS & HELPER FUNCTIONS ---
# ==============================================================================
def get_site_settings(): return {s.key: s.value for s in SiteSettings.query.all()}
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: return jsonify({"error": "Login required."}), 401
            if current_user.role != role_name and current_user.role != 'admin': return jsonify({"error": f"{role_name.capitalize()} access required."}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator
admin_required = role_required('admin')
teacher_required = role_required('teacher')
student_required = role_required('student')
def send_password_reset_email(user):
    try:
        token = password_reset_serializer.dumps(user.email, salt='password-reset-salt')
        reset_url = url_for('index', _external=True) + f"reset-password/{token}"
        msg = Message("Reset Your Password", recipients=[user.email], body=f"Click the link to reset your password: {reset_url}\nThis link is valid for one hour.")
        mail.send(msg)
        return True
    except Exception as e:
        logging.error(f"Email sending failed for {user.email}: {e}")
        return False
def generate_class_code():
    while True:
        code = secrets.token_hex(4).upper()
        if not Class.query.filter_by(code=code).first(): return code
def create_notification(user_id, content, url=None):
    notification = Notification(user_id=user_id, content=content, url=url)
    db.session.add(notification)
    db.session.commit()
    socketio.emit('new_notification', notification.to_dict(), room=f'user_{user_id}')
# ==============================================================================
# --- 5. FRONTEND & CORE ROUTES ---
# ==============================================================================
@app.route('/')
@app.route('/reset-password/<token>')
def index(token=None):
    nonce = secrets.token_hex(16)
    session['_csp_nonce'] = nonce
    final_html = HTML_CONTENT.replace('{csp_nonce}', nonce)
    return Response(final_html, mimetype='text/html')
@app.route('/api/status')
def status():
    config = {"email_enabled": bool(app.config.get('MAIL_SERVER'))}
    settings = get_site_settings()
    if current_user.is_authenticated: return jsonify({ "logged_in": True, "user": current_user.to_dict(), "settings": settings, "config": config })
    return jsonify({"logged_in": False, "config": config, "settings": settings})
# ==============================================================================
# --- 6. AUTHENTICATION API ROUTES ---
# ==============================================================================
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter(User.username.ilike(data.get('username'))).first()
    if user and user.password_hash and check_password_hash(user.password_hash, data.get('password', '')):
        login_user(user, remember=True)
        return jsonify({"success": True, "user": user.to_dict()})
    return jsonify({"error": "Invalid username or password."}), 401
@app.route('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify({"success": True})
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username, password, email = data.get('username','').strip(), data.get('password',''), data.get('email','').strip().lower()
    account_type = data.get('account_type', 'student')
    secret_key = data.get('secret_key')
    if not all([username, password, email]) or len(username) < 3 or len(password) < 6 or '@' not in email: return jsonify({"error": "Valid email, username (min 3 chars), and password (min 6 chars) are required."}), 400
    if User.query.filter(User.username.ilike(username)).first(): return jsonify({"error": "Username already exists."}), 409
    if User.query.filter(User.email.ilike(email)).first(): return jsonify({"error": "Email already in use."}), 409
    role = 'student'
    if account_type == 'teacher':
        if secret_key != SITE_CONFIG['SECRET_TEACHER_KEY']: return jsonify({"error": "Invalid teacher registration key."}), 403
        role = 'teacher'
    new_user = User(username=username, email=email, password_hash=generate_password_hash(password), role=role)
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user, remember=True)
    return jsonify({"success": True, "user": new_user.to_dict()})
@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    email = request.json.get('email', '').lower()
    user = User.query.filter_by(email=email).first()
    if user: send_password_reset_email(user)
    return jsonify({"message": "If an account with that email exists, a reset link has been sent."})
@app.route('/api/reset-with-token', methods=['POST'])
def reset_with_token():
    token, password = request.json.get('token'), request.json.get('password')
    try: email = password_reset_serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except (SignatureExpired, BadTimeSignature): return jsonify({"error": "The password reset link is invalid or has expired."}), 400
    user = User.query.filter_by(email=email).first()
    if not user: return jsonify({"error": "User not found."}), 404
    user.password_hash = generate_password_hash(password)
    db.session.commit()
    return jsonify({"message": "Password has been updated successfully."})
# ==============================================================================
# --- 7. ADMIN DASHBOARD API ROUTES ---
# ==============================================================================
@app.route('/api/admin/dashboard_data')
@admin_required
def admin_dashboard_data():
    users = User.query.order_by(User.created_at.desc()).all()
    classes = Class.query.all()
    stats = {
        'total_users': len(users), 'total_students': User.query.filter_by(role='student').count(),
        'total_teachers': User.query.filter_by(role='teacher').count(), 'total_classes': len(classes),
        'total_messages': Message.query.count(), 'total_assignments': Assignment.query.count(),
        'total_submissions': AssignmentSubmission.query.count(), 'total_quizzes': Quiz.query.count()
    }
    return jsonify({ "success": True, "stats": stats, "users": [u.to_dict() for u in users], "classes": [c.to_dict(student_count=True) for c in classes], "settings": get_site_settings() })
@app.route('/api/admin/update_settings', methods=['POST'])
@admin_required
def admin_update_settings():
    data = request.get_json()
    for key, value in data.items():
        setting = SiteSettings.query.get(key)
        if setting: setting.value = value
        else: db.session.add(SiteSettings(key=key, value=value))
    db.session.commit()
    return jsonify({"success": True, "message": "Settings updated."})
@app.route('/api/admin/user/<user_id>', methods=['PUT', 'DELETE'])
@admin_required
def admin_manage_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin': return jsonify({"error": "Cannot modify admin accounts."}), 403
    if request.method == 'DELETE':
        db.session.delete(user)
        db.session.commit()
        return jsonify({"success": True, "message": f"User {user.username} deleted."})
    if request.method == 'PUT':
        data = request.get_json()
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.role = data.get('role', user.role)
        if 'password' in data and data['password']: user.password_hash = generate_password_hash(data['password'])
        db.session.commit()
        return jsonify({"success": True, "user": user.to_dict()})
@app.route('/api/admin/class/<class_id>', methods=['DELETE'])
@admin_required
def admin_delete_class(class_id):
    cls = Class.query.get_or_404(class_id)
    db.session.delete(cls)
    db.session.commit()
    return jsonify({"success": True, "message": f"Class '{cls.name}' deleted."})
# ==============================================================================
# --- 8. CLASSES API ROUTES ---
# ==============================================================================
@app.route('/api/classes', methods=['POST'])
@teacher_required
def create_class():
    data = request.get_json()
    name = data.get('name')
    if not name: return jsonify({"error": "Class name is required."}), 400
    new_class = Class(name=name, code=generate_class_code(), teacher_id=current_user.id)
    db.session.add(new_class)
    db.session.commit()
    return jsonify({"success": True, "class": new_class.to_dict()})
@app.route('/api/my_classes', methods=['GET'])
@login_required
def my_classes():
    if current_user.role == 'teacher': classes = current_user.taught_classes
    elif current_user.role == 'student': classes = current_user.enrolled_classes.all()
    else: classes = Class.query.all()
    return jsonify({"success": True, "classes": [c.to_dict() for c in classes]})
@app.route('/api/classes/<class_id>', methods=['GET'])
@login_required
def get_class_details(class_id):
    cls = Class.query.get_or_404(class_id)
    if current_user.role != 'admin' and cls.teacher_id != current_user.id and not cls.students.filter_by(id=current_user.id).first(): return jsonify({"error": "Access denied."}), 403
    return jsonify({"success": True, "class": cls.to_dict(include_students=True)})
@app.route('/api/join_class', methods=['POST'])
@student_required
def join_class():
    data = request.get_json()
    code = data.get('code', '').upper()
    if not code: return jsonify({"error": "Class code is required."}), 400
    cls = Class.query.filter_by(code=code).first()
    if not cls: return jsonify({"error": "Invalid class code."}), 404
    if current_user in cls.students: return jsonify({"error": "Already in this class."}), 400
    cls.students.append(current_user)
    db.session.commit()
    create_notification(cls.teacher_id, f"Student '{current_user.username}' has joined your class '{cls.name}'.")
    return jsonify({"success": True, "message": f"Successfully joined {cls.name}."})
# ==============================================================================
# --- 9. PROFILE & PERKS API ROUTES ---
# ==============================================================================
@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    data = request.get_json()
    current_user.profile_bio = data.get('bio', current_user.profile_bio)[:500]
    current_user.profile_avatar = data.get('avatar', current_user.profile_avatar)
    db.session.commit()
    return jsonify({"success": True, "profile": {"bio": current_user.profile_bio, "avatar": current_user.profile_avatar}})
# ==============================================================================
# --- 10. MESSAGING & SOCKET.IO ROUTES ---
# ==============================================================================
@app.route('/api/class_messages/<class_id>', methods=['GET'])
@login_required
def get_class_messages(class_id):
    cls = Class.query.get_or_404(class_id)
    if current_user.role != 'admin' and cls.teacher_id != current_user.id and not cls.students.filter_by(id=current_user.id).first(): return jsonify({"error": "Access denied."}), 403
    messages = Message.query.filter_by(class_id=class_id).order_by(Message.timestamp.asc()).all()
    return jsonify({"success": True, "messages": [m.to_dict() for m in messages]})
@socketio.on('join')
def on_join(data):
    if not current_user.is_authenticated: return
    room = data['room']
    if room.startswith('class_'):
        class_id = room.split('_')[1]
        cls = Class.query.get(class_id)
        if not cls or (current_user.role != 'admin' and cls.teacher_id != current_user.id and not cls.students.filter_by(id=current_user.id).first()): return
    join_room(room)
@socketio.on('leave')
def on_leave(data):
    if not current_user.is_authenticated: return
    leave_room(data['room'])
@socketio.on('send_message')
def handle_send_message(json_data):
    class_id, content = json_data.get('class_id'), json_data.get('message')
    if not class_id or not content: return
    cls = Class.query.get(class_id)
    if not cls or (current_user.role != 'admin' and cls.teacher_id != current_user.id and not cls.students.filter_by(id=current_user.id).first()): return
    new_message = Message(class_id=class_id, sender_id=current_user.id, content=content)
    db.session.add(new_message)
    db.session.commit()
    emit('new_message', new_message.to_dict(), room=f'class_{class_id}')
    if current_user.role == 'student':
        ai_response_content = f"This is a placeholder AI response to: \"{content}\""
        ai_message = Message(class_id=class_id, sender_id=None, content=ai_response_content)
        db.session.add(ai_message)
        db.session.commit()
        emit('new_message', ai_message.to_dict(), room=f'class_{class_id}', broadcast=True)
# ==============================================================================
# --- 11. ASSIGNMENTS API ROUTES ---
# ==============================================================================
@app.route('/api/classes/<class_id>/assignments', methods=['GET', 'POST'])
@login_required
def manage_assignments(class_id):
    cls = Class.query.get_or_404(class_id)
    if request.method == 'GET':
        assignments = Assignment.query.filter_by(class_id=class_id).order_by(Assignment.due_date.desc()).all()
        return jsonify({"success": True, "assignments": [a.to_dict(student_id=current_user.id) for a in assignments]})
    if request.method == 'POST':
        if current_user.id != cls.teacher_id: return jsonify({"error": "Only the class teacher can create assignments."}), 403
        data = request.get_json()
        try: due_date = datetime.fromisoformat(data['due_date'].replace('Z', '+00:00'))
        except (ValueError, KeyError): return jsonify({"error": "Invalid date format for due_date."}), 400
        new_assignment = Assignment(title=data['title'], description=data['description'], due_date=due_date, class_id=class_id)
        db.session.add(new_assignment)
        db.session.commit()
        for student in cls.students: create_notification(student.id, f"New assignment '{new_assignment.title}' posted in '{cls.name}'.")
        return jsonify({"success": True, "assignment": new_assignment.to_dict()}), 201
@app.route('/api/assignments/<assignment_id>', methods=['GET'])
@login_required
def get_assignment_details(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)
    cls = assignment.class_obj
    if current_user.role != 'admin' and cls.teacher_id != current_user.id and not cls.students.filter_by(id=current_user.id).first(): return jsonify({"error": "Access denied."}), 403
    data = assignment.to_dict()
    if current_user.role == 'teacher' or current_user.role == 'admin': data['submissions'] = [s.to_dict() for s in assignment.submissions]
    else: data['my_submission'] = (s.to_dict() if (s := assignment.submissions.filter_by(student_id=current_user.id).first()) else None)
    return jsonify({"success": True, "assignment": data})
@app.route('/api/assignments/<assignment_id>/submissions', methods=['POST'])
@student_required
def submit_assignment(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)
    if current_user not in assignment.class_obj.students: return jsonify({"error": "You are not in this class."}), 403
    if AssignmentSubmission.query.filter_by(assignment_id=assignment_id, student_id=current_user.id).first(): return jsonify({"error": "You have already submitted this assignment."}), 409
    data = request.get_json()
    new_submission = AssignmentSubmission(assignment_id=assignment_id, student_id=current_user.id, content=data['content'])
    db.session.add(new_submission)
    db.session.commit()
    create_notification(assignment.class_obj.teacher_id, f"New submission for '{assignment.title}' from '{current_user.username}'.")
    return jsonify({"success": True, "submission": new_submission.to_dict()}), 201
@app.route('/api/submissions/<submission_id>/grade', methods=['POST'])
@teacher_required
def grade_submission(submission_id):
    submission = AssignmentSubmission.query.get_or_404(submission_id)
    if current_user.id != submission.assignment.class_obj.teacher_id: return jsonify({"error": "You are not authorized to grade this submission."}), 403
    data = request.get_json()
    submission.grade, submission.feedback = data.get('grade'), data.get('feedback')
    db.session.commit()
    create_notification(submission.student_id, f"Your assignment '{submission.assignment.title}' has been graded.")
    return jsonify({"success": True, "submission": submission.to_dict()})
# ==============================================================================
# --- 12. QUIZ API ROUTES ---
# ==============================================================================
@app.route('/api/classes/<class_id>/quizzes', methods=['GET', 'POST'])
@login_required
def manage_quizzes(class_id):
    cls = Class.query.get_or_404(class_id)
    if request.method == 'GET':
        quizzes = Quiz.query.filter_by(class_id=class_id).order_by(Quiz.id.desc()).all()
        return jsonify({"success": True, "quizzes": [q.to_dict(student_id=current_user.id) for q in quizzes]})
    if request.method == 'POST':
        if current_user.id != cls.teacher_id: return jsonify({"error": "Only the class teacher can create quizzes."}), 403
        data = request.get_json()
        new_quiz = Quiz(title=data['title'], description=data.get('description', ''), time_limit=int(data['time_limit']), class_id=class_id)
        db.session.add(new_quiz)
        for i, q_data in enumerate(data['questions']):
            question = Question(quiz=new_quiz, text=q_data['text'], question_type=q_data['type'], order=i)
            db.session.add(question)
            if q_data['type'] == 'multiple_choice':
                for c_data in q_data['choices']:
                    choice = Choice(question=question, text=c_data['text'], is_correct=c_data['is_correct'])
                    db.session.add(choice)
        db.session.commit()
        for student in cls.students: create_notification(student.id, f"New quiz '{new_quiz.title}' posted in '{cls.name}'.")
        return jsonify({"success": True, "quiz": new_quiz.to_dict()}), 201
@app.route('/api/quizzes/<quiz_id>', methods=['GET'])
@login_required
def get_quiz_details(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    cls = quiz.class_obj
    if current_user.role != 'admin' and cls.teacher_id != current_user.id and not cls.students.filter_by(id=current_user.id).first(): return jsonify({"error": "Access denied."}), 403
    data = quiz.to_dict()
    if current_user.role == 'teacher' or current_user.role == 'admin':
        data['questions'] = [q.to_dict(include_correct=True) for q in quiz.questions]
        data['attempts'] = [a.to_dict() for a in quiz.attempts]
    return jsonify({"success": True, "quiz": data})
@app.route('/api/quizzes/<quiz_id>/start', methods=['POST'])
@student_required
def start_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    if current_user not in quiz.class_obj.students: return jsonify({"error": "You are not enrolled in this class."}), 403
    if QuizAttempt.query.filter_by(quiz_id=quiz_id, student_id=current_user.id).first(): return jsonify({"error": "You have already attempted this quiz."}), 409
    attempt = QuizAttempt(quiz_id=quiz_id, student_id=current_user.id)
    db.session.add(attempt)
    db.session.commit()
    questions = [q.to_dict() for q in quiz.questions.order_by(Question.order)]
    return jsonify({"success": True, "attempt_id": attempt.id, "questions": questions, "time_limit": quiz.time_limit, "start_time": attempt.start_time.isoformat()})
@app.route('/api/attempts/<attempt_id>/submit', methods=['POST'])
@student_required
def submit_quiz(attempt_id):
    attempt = QuizAttempt.query.get_or_404(attempt_id)
    if attempt.student_id != current_user.id: return jsonify({"error": "This is not your attempt."}), 403
    if attempt.end_time: return jsonify({"error": "This quiz has already been submitted."}), 409
    
    time_limit = timedelta(minutes=attempt.quiz.time_limit)
    if datetime.utcnow() > attempt.start_time + time_limit:
        # Handle late submission if needed, for now just mark end time
        attempt.end_time = attempt.start_time + time_limit
    else:
        attempt.end_time = datetime.utcnow()
    
    answers_data = request.get_json().get('answers', {})
    total_questions = attempt.quiz.questions.count()
    correct_answers = 0

    for q in attempt.quiz.questions:
        student_answer = answers_data.get(q.id)
        is_correct = False
        if q.question_type == 'multiple_choice' and student_answer:
            correct_choice = q.choices.filter_by(is_correct=True).first()
            if correct_choice and student_answer == correct_choice.id:
                is_correct = True
            answer = Answer(attempt_id=attempt.id, question_id=q.id, choice_id=student_answer, is_correct=is_correct)
            db.session.add(answer)
        # Add logic for short_answer grading if needed (e.g., manual grading)
        
        if is_correct: correct_answers += 1
        
    attempt.score = (correct_answers / total_questions) * 100 if total_questions > 0 else 0
    db.session.commit()
    create_notification(attempt.quiz.class_obj.teacher_id, f"'{current_user.username}' submitted the quiz '{attempt.quiz.title}'.")
    return jsonify({"success": True, "attempt": attempt.to_dict()})
# ==============================================================================
# --- 13. NOTIFICATIONS API ---
# ==============================================================================
@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).limit(20).all()
    return jsonify({"success": True, "notifications": [n.to_dict() for n in notifications]})
@app.route('/api/notifications/mark_read', methods=['POST'])
@login_required
def mark_notifications_read():
    data = request.get_json()
    ids = data.get('ids', [])
    query = Notification.query.filter_by(user_id=current_user.id)
    if ids: query = query.filter(Notification.id.in_(ids))
    query.update({'is_read': True}, synchronize_session=False)
    db.session.commit()
    return jsonify({"success": True})
# ==============================================================================
# --- 14. STRIPE PAYMENT INTEGRATION ---
# ==============================================================================
@app.route('/api/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    data = request.get_json()
    price_id = data.get('price_id')
    if not price_id: return jsonify({'error': 'Price ID is required'}), 400
    try:
        customer_id = current_user.stripe_customer_id
        if not customer_id:
            customer = stripe.Customer.create(email=current_user.email, name=current_user.username)
            current_user.stripe_customer_id = customer.id
            db.session.commit()
            customer_id = customer.id
        checkout_session = stripe.checkout.Session.create(
            customer=customer_id, line_items=[{'price': price_id, 'quantity': 1}], mode='subscription',
            success_url=SITE_CONFIG['YOUR_DOMAIN'] + '?session_id={CHECKOUT_SESSION_ID}', cancel_url=SITE_CONFIG['YOUR_DOMAIN'],
        )
        return jsonify({'sessionId': checkout_session.id})
    except Exception as e: return jsonify(error=str(e)), 403
@app.route('/api/create-customer-portal-session', methods=['POST'])
@login_required
def customer_portal():
    if not current_user.stripe_customer_id: return jsonify({"error": "User is not a Stripe customer."}), 400
    try:
        portal_session = stripe.billing_portal.Session.create(customer=current_user.stripe_customer_id, return_url=SITE_CONFIG['YOUR_DOMAIN'])
        return jsonify({'url': portal_session.url})
    except Exception as e: return jsonify(error=str(e)), 400
@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload, sig_header = request.get_data(as_text=True), request.headers.get('Stripe-Signature')
    try: event = stripe.Webhook.construct_event(payload, sig_header, SITE_CONFIG['STRIPE_WEBHOOK_SECRET'])
    except (ValueError, stripe.error.SignatureVerificationError) as e: return 'Invalid payload or signature', 400
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user = User.query.filter_by(stripe_customer_id=session.get('customer')).first()
        if user:
            user.stripe_subscription_id = session.get('subscription')
            user.plan = 'pro' # Simplified
            db.session.commit()
    elif event['type'] in ['customer.subscription.deleted', 'customer.subscription.updated']:
        session = event['data']['object']
        user = User.query.filter_by(stripe_customer_id=session.get('customer')).first()
        if user:
            if event['type'] == 'customer.subscription.deleted' or session.get('cancel_at_period_end'):
                user.plan, user.stripe_subscription_id = 'free', None
            else: user.plan = 'pro'
            db.session.commit()
    return 'Success', 200
# ==============================================================================
# --- 15. HTML & JAVASCRIPT FRONTEND ---
# ==============================================================================
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" /><title>Myth AI Portal</title>
    <script src="https://cdn.tailwindcss.com"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script><script src="https://js.stripe.com/v3/"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { background-color: #111827; font-family: 'Inter', sans-serif; }
        .glassmorphism { background: rgba(31, 41, 55, 0.5); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.1); }
        .brand-gradient { background-image: linear-gradient(to right, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .fade-in { animation: fadeIn 0.5s ease-out forwards; } @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .active-tab { background-color: #374151; color: white; border-bottom: 2px solid #3b82f6; }
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 1000; }
        .modal-content { max-height: 90vh; overflow-y: auto; } .loader { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body class="text-gray-200 antialiased">
    <div id="announcement-banner" class="hidden text-center p-2 bg-indigo-600 text-white text-sm"></div>
    <div id="app-container" class="relative h-screen w-screen overflow-hidden"></div>
    <div id="toast-container" class="fixed top-6 right-6 z-[100] flex flex-col gap-2"></div>
    <div id="modal-container"></div>
    <!-- TEMPLATES START -->
    <template id="template-auth-page"><div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4 fade-in"><div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl"><h1 class="text-4xl font-bold text-center brand-gradient mb-4">Myth AI Portal</h1><p class="text-gray-400 text-center mb-8" id="auth-subtitle">Sign in to continue</p><form id="auth-form"><div class="mb-4"><label for="username" class="block text-sm font-medium text-gray-300 mb-1">Username</label><input type="text" id="username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div class="mb-4"><label for="password" class="block text-sm font-medium text-gray-300 mb-1">Password</label><input type="password" id="password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div class="flex justify-end mb-6"><button type="button" id="forgot-password-link" class="text-xs text-blue-400 hover:text-blue-300">Forgot Password?</button></div><button type="submit" id="auth-submit-btn" class="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg transition-opacity">Login</button><p id="auth-error" class="text-red-400 text-sm text-center h-4 mt-3"></p></form><div class="text-center mt-6"><button id="auth-toggle-btn" class="text-sm text-blue-400 hover:text-blue-300">Don't have an account? Sign Up</button></div><div class="text-center mt-4"><button id="teacher-signup-btn" class="text-sm text-green-400 hover:text-green-300">Sign Up as Teacher</button></div></div></div></template>
    <template id="template-signup-page"><div class="flex flex-col items-center justify-center h-full w-full bg-gray-900 p-4 fade-in"><div class="w-full max-w-md glassmorphism rounded-2xl p-8 shadow-2xl"><h2 class="text-3xl font-bold text-center text-white mb-2" id="signup-title">Create Account</h2><p class="text-gray-400 text-center mb-8" id="signup-subtitle">Begin your journey.</p><form id="signup-form"><input type="hidden" id="account_type" name="account_type" value="student"><div class="mb-4"><label for="signup-username" class="block text-sm font-medium text-gray-300 mb-1">Username</label><input type="text" id="signup-username" name="username" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required minlength="3"></div><div class="mb-4"><label for="signup-email" class="block text-sm font-medium text-gray-300 mb-1">Email</label><input type="email" id="signup-email" name="email" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required></div><div class="mb-4"><label for="signup-password" class="block text-sm font-medium text-gray-300 mb-1">Password (min. 6 characters)</label><input type="password" id="signup-password" name="password" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" required minlength="6"></div><div id="teacher-key-field" class="hidden mb-4"><label for="teacher-secret-key" class="block text-sm font-medium text-gray-300 mb-1">Secret Teacher Key</label><input type="text" id="teacher-secret-key" name="secret_key" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><button type="submit" class="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:opacity-90 text-white font-bold py-3 px-4 rounded-lg">Sign Up</button><p id="signup-error" class="text-red-400 text-sm text-center h-4 mt-3"></p></form><div class="text-center mt-6"><button id="back-to-login" class="text-sm text-blue-400 hover:text-blue-300">Back to Login</button></div></div></div></template>
    <template id="template-main-dashboard"><div class="flex h-full w-full bg-gray-800 fade-in"><nav class="w-64 bg-gray-900 p-6 flex flex-col gap-4 flex-shrink-0"><h2 class="text-2xl font-bold text-white mb-4" id="dashboard-title">Dashboard</h2><div id="nav-links" class="flex flex-col gap-2"></div><div class="mt-auto flex flex-col gap-4"><div id="notification-bell-container" class="relative"></div><button id="logout-btn" class="bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded-lg">Logout</button></div></nav><main class="flex-1 p-8 overflow-y-auto"><div id="dashboard-content"></div></main></div></template>
    <template id="template-my-classes"><h3 class="text-3xl font-bold text-white mb-6">My Classes</h3><div id="class-action-container" class="mb-6"></div><div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="classes-list"></div><div id="selected-class-view" class="mt-8 hidden"></div></template>
    <template id="template-student-class-action"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Join a New Class</h4><div class="flex items-center gap-2"><input type="text" id="class-code" placeholder="Enter class code" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="join-class-btn" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 px-4 rounded-lg">Join</button></div></div></template>
    <template id="template-teacher-class-action"><div class="glassmorphism p-4 rounded-lg"><h4 class="font-semibold text-lg mb-2 text-white">Create a New Class</h4><div class="flex items-center gap-2"><input type="text" id="new-class-name" placeholder="New class name" class="flex-grow p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button id="create-class-btn" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 px-4 rounded-lg">Create</button></div></div></template>
    <template id="template-selected-class-view"><div class="glassmorphism p-6 rounded-lg"><div class="flex justify-between items-start"><h4 class="text-2xl font-bold text-white mb-4">Class: <span id="selected-class-name"></span></h4><button id="back-to-classes-btn" class="text-sm text-blue-400 hover:text-blue-300">&larr; Back to All Classes</button></div><div class="flex border-b border-gray-600 mb-4"><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab" data-tab="chat">Chat</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab" data-tab="assignments">Assignments</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab" data-tab="quizzes">Quizzes</button><button class="py-2 px-4 text-gray-300 hover:text-white class-view-tab" data-tab="students">Students</button></div><div id="class-view-content"></div></div></template>
    <template id="template-class-chat-view"><div id="chat-messages" class="bg-gray-900/50 p-4 rounded-lg h-80 overflow-y-auto mb-4 border border-gray-700"></div><form id="chat-form" class="flex items-center gap-2"><input type="text" id="chat-input" placeholder="Type a message..." class="flex-grow w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"><button type="submit" id="send-chat-btn" class="bg-green-600 hover:bg-green-500 text-white font-bold py-3 px-4 rounded-lg">Send</button></form></template>
    <template id="template-class-assignments-view"><div class="flex justify-between items-center mb-4"><h5 class="text-xl font-semibold text-white">Assignments</h5><div id="assignment-action-container"></div></div><div id="assignments-list" class="space-y-4"></div></template>
    <template id="template-class-quizzes-view"><div class="flex justify-between items-center mb-4"><h5 class="text-xl font-semibold text-white">Quizzes</h5><div id="quiz-action-container"></div></div><div id="quizzes-list" class="space-y-4"></div></template>
    <template id="template-class-students-view"><h5 class="text-xl font-semibold text-white mb-4">Enrolled Students</h5><ul id="class-students-list" class="space-y-2"></ul></template>
    <template id="template-profile"><h3 class="text-3xl font-bold text-white mb-6">Customize Profile</h3><form id="profile-form" class="glassmorphism p-6 rounded-lg max-w-lg"><div class="mb-4"><label for="bio" class="block text-sm font-medium text-gray-300 mb-1">Bio</label><textarea id="bio" name="bio" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600" rows="4"></textarea></div><div class="mb-4"><label for="avatar" class="block text-sm font-medium text-gray-300 mb-1">Avatar URL</label><input type="url" id="avatar" name="avatar" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg">Save Profile</button></form></template>
    <template id="template-billing"><h3 class="text-3xl font-bold text-white mb-6">Billing & Subscriptions</h3><div id="billing-content" class="glassmorphism p-6 rounded-lg"></div></template>
    <template id="template-admin-dashboard"><h3 class="text-3xl font-bold text-white mb-6">Admin Dashboard</h3><div id="admin-stats" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8"></div><div class="flex border-b border-gray-600 mb-4"><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab" data-tab="users">Users</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab" data-tab="classes">Classes</button><button class="py-2 px-4 text-gray-300 hover:text-white admin-view-tab" data-tab="settings">Settings</button></div><div id="admin-view-content"></div></template>
    <template id="template-admin-users-view"><h4 class="text-xl font-bold text-white mb-4">User Management</h4><div class="overflow-x-auto glassmorphism p-4 rounded-lg"><table class="w-full text-left text-sm text-gray-300"><thead><tr class="border-b border-gray-600"><th class="p-3">Username</th><th class="p-3">Email</th><th class="p-3">Role</th><th class="p-3">Created At</th><th class="p-3">Actions</th></tr></thead><tbody id="admin-user-list" class="divide-y divide-gray-700/50"></tbody></table></div></template>
    <template id="template-admin-classes-view"><h4 class="text-xl font-bold text-white mb-4">Class Management</h4><div class="overflow-x-auto glassmorphism p-4 rounded-lg"><table class="w-full text-left text-sm text-gray-300"><thead><tr class="border-b border-gray-600"><th class="p-3">Name</th><th class="p-3">Teacher</th><th class="p-3">Code</th><th class="p-3">Students</th><th class="p-3">Actions</th></tr></thead><tbody id="admin-class-list" class="divide-y divide-gray-700/50"></tbody></table></div></template>
    <template id="template-admin-settings-view"><h4 class="text-xl font-bold text-white mb-4">Site Settings</h4><form id="admin-settings-form" class="glassmorphism p-6 rounded-lg max-w-lg"><div class="mb-4"><label for="setting-announcement" class="block text-sm font-medium text-gray-300 mb-1">Announcement Banner</label><input type="text" id="setting-announcement" name="announcement" class="w-full p-3 bg-gray-700/50 rounded-lg border border-gray-600"></div><button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg">Save Settings</button></form></template>
    <template id="template-modal"><div class="modal-overlay"><div class="glassmorphism rounded-2xl p-8 shadow-2xl w-full max-w-2xl modal-content relative"><button class="absolute top-4 right-4 text-gray-400 hover:text-white">&times;</button><div class="modal-body"></div></div></div></template>
    <!-- TEMPLATES END -->
    <script nonce="{csp_nonce}">
    document.addEventListener('DOMContentLoaded', () => {
        const appState = { currentUser: null, currentTab: 'my-classes', selectedClass: null, socket: null, stripe: null, quizTimer: null };
        const DOMElements = { appContainer: document.getElementById('app-container'), toastContainer: document.getElementById('toast-container'), announcementBanner: document.getElementById('announcement-banner'), modalContainer: document.getElementById('modal-container') };
        function showToast(message, type = 'info') { const colors = { info: 'bg-blue-600', success: 'bg-green-600', error: 'bg-red-600' }; const toast = document.createElement('div'); toast.className = `text-white text-sm py-2 px-4 rounded-lg shadow-lg fade-in ${colors[type]}`; toast.textContent = message; DOMElements.toastContainer.appendChild(toast); setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 500); }, 3500); }
        async function apiCall(endpoint, options = {}) { try { if (options.body && typeof options.body === 'object') { options.headers = { 'Content-Type': 'application/json', ...options.headers }; options.body = JSON.stringify(options.body); } const response = await fetch(endpoint, { credentials: 'include', ...options }); const data = await response.json(); if (!response.ok) { if (response.status === 401 && !window.location.pathname.includes('reset-password')) handleLogout(false); throw new Error(data.error || `Request failed with status ${response.status}`); } return { success: true, ...data }; } catch (error) { showToast(error.message, 'error'); console.error("API Call Error:", error); return { success: false, error: error.message }; } }
        function renderPage(templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) { console.error(`Template ${templateId} not found.`); return; } const content = template.content.cloneNode(true); DOMElements.appContainer.innerHTML = ''; DOMElements.appContainer.appendChild(content); if (setupFunction) setupFunction(); }
        function renderSubTemplate(container, templateId, setupFunction) { const template = document.getElementById(templateId); if (!template) return; const content = template.content.cloneNode(true); container.innerHTML = ''; container.appendChild(content); if (setupFunction) setupFunction(); }
        function showModal(content, setupFunction, maxWidth = 'max-w-2xl') { const template = document.getElementById('template-modal').content.cloneNode(true); const modalBody = template.querySelector('.modal-body'); modalBody.innerHTML = content; template.querySelector('.modal-content').classList.replace('max-w-2xl', maxWidth); template.querySelector('button').addEventListener('click', hideModal); DOMElements.modalContainer.innerHTML = ''; DOMElements.modalContainer.appendChild(template); if(setupFunction) setupFunction(DOMElements.modalContainer); }
        function hideModal() { DOMElements.modalContainer.innerHTML = ''; }
        function connectSocket() { if (appState.socket) appState.socket.disconnect(); appState.socket = io(); appState.socket.on('connect', () => { console.log('Socket connected!'); appState.socket.emit('join', { room: `user_${appState.currentUser.id}` }); }); appState.socket.on('new_message', (data) => { if (appState.selectedClass && data.class_id === appState.selectedClass.id) appendChatMessage(data); }); appState.socket.on('new_notification', (data) => { showToast(`Notification: ${data.content}`, 'info'); updateNotificationBell(true); }); }
        function setupAuthPage() { renderPage('template-auth-page', () => { document.getElementById('auth-form').addEventListener('submit', handleLoginSubmit); document.getElementById('auth-toggle-btn').addEventListener('click', () => setupSignupPage('student')); document.getElementById('teacher-signup-btn').addEventListener('click', () => setupSignupPage('teacher')); document.getElementById('forgot-password-link').addEventListener('click', handleForgotPassword); }); }
        function setupSignupPage(type = 'student') { renderPage('template-signup-page', () => { document.getElementById('signup-form').addEventListener('submit', handleSignupSubmit); document.getElementById('back-to-login').addEventListener('click', setupAuthPage); const title = document.getElementById('signup-title'), subtitle = document.getElementById('signup-subtitle'); const accountTypeInput = document.getElementById('account_type'), teacherKeyField = document.getElementById('teacher-key-field'); if (type === 'teacher') { title.textContent = 'Create Teacher Account'; subtitle.textContent = 'A valid secret key is required.'; accountTypeInput.value = 'teacher'; teacherKeyField.classList.remove('hidden'); teacherKeyField.querySelector('input').required = true; } else { title.textContent = 'Create Student Account'; subtitle.textContent = 'Begin your learning journey.'; accountTypeInput.value = 'student'; teacherKeyField.classList.add('hidden'); teacherKeyField.querySelector('input').required = false; } }); }
        function setupDashboard() { const user = appState.currentUser; if (!user) return setupAuthPage(); connectSocket(); renderPage('template-main-dashboard', () => { const navLinks = document.getElementById('nav-links'), dashboardTitle = document.getElementById('dashboard-title'); let tabs = []; if (user.role === 'student' || user.role === 'teacher') { dashboardTitle.textContent = `${user.role.charAt(0).toUpperCase() + user.role.slice(1)} Portal`; tabs = [{ id: 'my-classes', label: 'My Classes' }, { id: 'billing', label: 'Billing' }, { id: 'profile', label: 'Profile' }]; } else if (user.role === 'admin') { dashboardTitle.textContent = 'Admin Dashboard'; tabs = [{ id: 'admin-dashboard', label: 'Dashboard' }, { id: 'profile', label: 'My Profile' }]; appState.currentTab = 'admin-dashboard'; } navLinks.innerHTML = tabs.map(tab => `<button data-tab="${tab.id}" class="dashboard-tab text-left text-gray-300 hover:text-white p-2 rounded-md">${tab.label}</button>`).join(''); document.querySelectorAll('.dashboard-tab').forEach(tab => tab.addEventListener('click', () => switchTab(tab.dataset.tab))); document.getElementById('logout-btn').addEventListener('click', () => handleLogout(true)); setupNotificationBell(); switchTab(appState.currentTab); }); }
        function switchTab(tab) { appState.currentTab = tab; appState.selectedClass = null; document.querySelectorAll('.dashboard-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === tab)); const contentContainer = document.getElementById('dashboard-content'); const setups = { 'my-classes': setupMyClassesTab, 'profile': setupProfileTab, 'billing': setupBillingTab, 'admin-dashboard': setupAdminDashboardTab }; if (setups[tab]) setups[tab](contentContainer); }
        async function setupMyClassesTab(container) { renderSubTemplate(container, 'template-my-classes', async () => { const actionContainer = document.getElementById('class-action-container'), listContainer = document.getElementById('classes-list'); const actionTemplateId = `template-${appState.currentUser.role}-class-action`; renderSubTemplate(actionContainer, actionTemplateId, () => { if (appState.currentUser.role === 'student') document.getElementById('join-class-btn').addEventListener('click', handleJoinClass); else document.getElementById('create-class-btn').addEventListener('click', handleCreateClass); }); const result = await apiCall('/api/my_classes'); if (result.success && result.classes) { if (result.classes.length === 0) listContainer.innerHTML = `<p class="text-gray-400 text-center col-span-full">You haven't joined or created any classes yet.</p>`; else listContainer.innerHTML = result.classes.map(cls => `<div class="glassmorphism p-4 rounded-lg cursor-pointer hover:bg-gray-700/50 transition-colors" data-id="${cls.id}" data-name="${cls.name}"><div class="font-bold text-white text-lg">${cls.name}</div><div class="text-gray-400 text-sm">Teacher: ${cls.teacher_name}</div>${appState.currentUser.role === 'teacher' ? `<div class="text-sm mt-2">Code: <span class="font-mono text-cyan-400">${cls.code}</span></div>` : ''}</div>`).join(''); listContainer.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', (e) => selectClass(e.currentTarget.dataset.id))); } }); }
        function setupProfileTab(container) { renderSubTemplate(container, 'template-profile', () => { document.getElementById('bio').value = appState.currentUser.profile.bio || ''; document.getElementById('avatar').value = appState.currentUser.profile.avatar || ''; document.getElementById('profile-form').addEventListener('submit', handleUpdateProfile); }); }
        function setupBillingTab(container) { renderSubTemplate(container, 'template-billing', () => { const content = document.getElementById('billing-content'); if (appState.currentUser.has_subscription) { content.innerHTML = `<p class="mb-4">You have an active subscription. Manage your subscription, view invoices, and update payment methods through the customer portal.</p><button id="manage-billing-btn" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg">Manage Billing</button>`; document.getElementById('manage-billing-btn').addEventListener('click', handleManageBilling); } else { content.innerHTML = `<p class="mb-4">Upgrade to a Pro plan for unlimited AI interactions and more features!</p><button id="upgrade-btn" data-price-id="${SITE_CONFIG.STRIPE_STUDENT_PRO_PRICE_ID}" class="bg-green-600 hover:bg-green-500 text-white font-bold py-2 px-4 rounded-lg">Upgrade to Pro</button>`; document.getElementById('upgrade-btn').addEventListener('click', handleUpgrade); } }); }
        async function setupAdminDashboardTab(container) { renderSubTemplate(container, 'template-admin-dashboard', async () => { const result = await apiCall('/api/admin/dashboard_data'); if (result.success) { document.getElementById('admin-stats').innerHTML = Object.entries(result.stats).map(([key, value]) => `<div class="glassmorphism p-4 rounded-lg"><p class="text-sm text-gray-400">${key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</p><p class="text-2xl font-bold">${value}</p></div>`).join(''); } document.querySelectorAll('.admin-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchAdminView(e.currentTarget.dataset.tab))); switchAdminView('users'); }); }
        async function switchAdminView(view) { document.querySelectorAll('.admin-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view)); const container = document.getElementById('admin-view-content'); const result = await apiCall('/api/admin/dashboard_data'); if(!result.success) return; if (view === 'users') { renderSubTemplate(container, 'template-admin-users-view', () => { const userList = document.getElementById('admin-user-list'); userList.innerHTML = result.users.map(u => `<tr><td class="p-3">${u.username}</td><td class="p-3">${u.email}</td><td class="p-3">${u.role}</td><td class="p-3">${new Date(u.created_at).toLocaleDateString()}</td><td class="p-3 space-x-2"><button class="text-blue-400 hover:text-blue-300" data-action="edit" data-id="${u.id}">Edit</button><button class="text-red-500 hover:text-red-400" data-action="delete" data-id="${u.id}">Delete</button></td></tr>`).join(''); userList.querySelectorAll('button').forEach(btn => btn.addEventListener('click', (e) => handleAdminUserAction(e.currentTarget.dataset.action, e.currentTarget.dataset.id))); }); } else if (view === 'classes') { renderSubTemplate(container, 'template-admin-classes-view', () => { document.getElementById('admin-class-list').innerHTML = result.classes.map(c => `<tr><td class="p-3">${c.name}</td><td class="p-3">${c.teacher_name}</td><td class="p-3">${c.code}</td><td class="p-3">${c.student_count}</td><td class="p-3"><button class="text-red-500 hover:text-red-400" data-id="${c.id}">Delete</button></td></tr>`).join(''); document.getElementById('admin-class-list').querySelectorAll('button').forEach(btn => btn.addEventListener('click', (e) => handleAdminDeleteClass(e.currentTarget.dataset.id))); }); } else if (view === 'settings') { renderSubTemplate(container, 'template-admin-settings-view', () => { document.getElementById('setting-announcement').value = result.settings.announcement || ''; document.getElementById('admin-settings-form').addEventListener('submit', handleAdminUpdateSettings); }); } }
        async function handleLoginSubmit(e) { e.preventDefault(); const result = await apiCall('/api/login', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) }); if (result.success) initializeApp(result.user, result.settings); else document.getElementById('auth-error').textContent = result.error; }
        async function handleSignupSubmit(e) { e.preventDefault(); const result = await apiCall('/api/signup', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) }); if (result.success) initializeApp(result.user, {}); else document.getElementById('signup-error').textContent = result.error; }
        async function handleForgotPassword() { const email = prompt('Please enter your account email address:'); if (email && /^\\S+@\\S+\\.\\S+$/.test(email)) { const result = await apiCall('/api/request-password-reset', { method: 'POST', body: { email } }); if(result.success) showToast(result.message || 'Request sent.', 'info'); } else if (email) showToast('Please enter a valid email address.', 'error'); }
        async function handleLogout(doApiCall) { if (doApiCall) await apiCall('/api/logout'); if (appState.socket) appState.socket.disconnect(); appState.currentUser = null; window.location.replace('/'); }
        async function handleJoinClass() { const codeInput = document.getElementById('class-code'); const code = codeInput.value.trim().toUpperCase(); if (!code) return showToast('Please enter a class code.', 'error'); const result = await apiCall('/api/join_class', { method: 'POST', body: { code } }); if (result.success) { showToast(result.message || 'Joined class!', 'success'); codeInput.value = ''; setupMyClassesTab(document.getElementById('dashboard-content')); } }
        async function handleCreateClass() { const nameInput = document.getElementById('new-class-name'); const name = nameInput.value.trim(); if (!name) return showToast('Please enter a class name.', 'error'); const result = await apiCall('/api/classes', { method: 'POST', body: { name } }); if (result.success) { showToast(`Class "${result.class.name}" created!`, 'success'); nameInput.value = ''; setupMyClassesTab(document.getElementById('dashboard-content')); } }
        async function selectClass(classId) { if (appState.selectedClass && appState.socket) appState.socket.emit('leave', { room: `class_${appState.selectedClass.id}` }); const result = await apiCall(`/api/classes/${classId}`); if(!result.success) return; appState.selectedClass = result.class; appState.socket.emit('join', { room: `class_${classId}` }); document.getElementById('classes-list').classList.add('hidden'); document.getElementById('class-action-container').classList.add('hidden'); const viewContainer = document.getElementById('selected-class-view'); viewContainer.classList.remove('hidden'); renderSubTemplate(viewContainer, 'template-selected-class-view', () => { document.getElementById('selected-class-name').textContent = appState.selectedClass.name; document.getElementById('back-to-classes-btn').addEventListener('click', () => { viewContainer.classList.add('hidden'); document.getElementById('classes-list').classList.remove('hidden'); document.getElementById('class-action-container').classList.remove('hidden'); }); document.querySelectorAll('.class-view-tab').forEach(tab => tab.addEventListener('click', (e) => switchClassView(e.currentTarget.dataset.tab))); switchClassView('chat'); }); }
        function switchClassView(view) { document.querySelectorAll('.class-view-tab').forEach(t => t.classList.toggle('active-tab', t.dataset.tab === view)); const container = document.getElementById('class-view-content'); if (view === 'chat') { renderSubTemplate(container, 'template-class-chat-view', async () => { document.getElementById('chat-form').addEventListener('submit', handleSendChat); const result = await apiCall(`/api/class_messages/${appState.selectedClass.id}`); if (result.success) { const messagesDiv = document.getElementById('chat-messages'); messagesDiv.innerHTML = ''; result.messages.forEach(m => appendChatMessage(m)); } }); } else if (view === 'assignments') { renderSubTemplate(container, 'template-class-assignments-view', async () => { const list = document.getElementById('assignments-list'); const actionContainer = document.getElementById('assignment-action-container'); if(appState.currentUser.role === 'teacher') { actionContainer.innerHTML = `<button id="create-assignment-btn" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg">New Assignment</button>`; document.getElementById('create-assignment-btn').addEventListener('click', handleCreateAssignment); } const result = await apiCall(`/api/classes/${appState.selectedClass.id}/assignments`); if(result.success) { if(result.assignments.length === 0) list.innerHTML = `<p class="text-gray-400">No assignments posted yet.</p>`; else list.innerHTML = result.assignments.map(a => `<div class="p-4 bg-gray-800/50 rounded-lg cursor-pointer" data-id="${a.id}"><div class="flex justify-between items-center"><h6 class="font-bold text-white">${a.title}</h6><span class="text-sm text-gray-400">Due: ${new Date(a.due_date).toLocaleDateString()}</span></div>${appState.currentUser.role === 'student' ? (a.student_submission ? `<span class="text-xs text-green-400">Submitted</span>` : `<span class="text-xs text-yellow-400">Not Submitted</span>`) : `<span class="text-xs text-cyan-400">${a.submission_count} Submissions</span>`}</div>`).join(''); list.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => viewAssignmentDetails(e.currentTarget.dataset.id))); } }); } else if (view === 'quizzes') { renderSubTemplate(container, 'template-class-quizzes-view', async () => { const list = document.getElementById('quizzes-list'); const actionContainer = document.getElementById('quiz-action-container'); if(appState.currentUser.role === 'teacher') { actionContainer.innerHTML = `<button id="create-quiz-btn" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg">New Quiz</button>`; document.getElementById('create-quiz-btn').addEventListener('click', handleCreateQuiz); } const result = await apiCall(`/api/classes/${appState.selectedClass.id}/quizzes`); if(result.success) { if(result.quizzes.length === 0) list.innerHTML = `<p class="text-gray-400">No quizzes posted yet.</p>`; else list.innerHTML = result.quizzes.map(q => `<div class="p-4 bg-gray-800/50 rounded-lg cursor-pointer" data-id="${q.id}"><div class="flex justify-between items-center"><h6 class="font-bold text-white">${q.title}</h6><span class="text-sm text-gray-400">${q.time_limit} mins</span></div>${appState.currentUser.role === 'student' ? (q.student_attempt ? `<span class="text-xs text-green-400">Attempted - Score: ${q.student_attempt.score.toFixed(2)}%</span>` : `<span class="text-xs text-yellow-400">Not Attempted</span>`) : ``}</div>`).join(''); list.querySelectorAll('div[data-id]').forEach(el => el.addEventListener('click', e => viewQuizDetails(e.currentTarget.dataset.id))); } }); } else if (view === 'students') { renderSubTemplate(container, 'template-class-students-view', () => { document.getElementById('class-students-list').innerHTML = appState.selectedClass.students.map(s => `<li class="flex items-center gap-3 p-2 bg-gray-800/50 rounded-md"><img src="${s.profile.avatar || `https://i.pravatar.cc/40?u=${s.id}`}" class="w-8 h-8 rounded-full"><span>${s.username}</span></li>`).join(''); }); } }
        function handleSendChat(e) { e.preventDefault(); const input = document.getElementById('chat-input'); const message = input.value.trim(); if (!message || !appState.socket) return; appState.socket.emit('send_message', { class_id: appState.selectedClass.id, message: message }); input.value = ''; input.focus(); }
        function appendChatMessage(message) { const messagesDiv = document.getElementById('chat-messages'); if (!messagesDiv) return; const isCurrentUser = message.sender_id === appState.currentUser.id; const isAI = message.sender_id === null; let senderClass = 'text-yellow-400'; if (isCurrentUser) senderClass = 'text-green-400'; if (isAI) senderClass = 'text-cyan-400'; const msgEl = document.createElement('div'); msgEl.className = 'mb-2 text-sm'; msgEl.innerHTML = `<span class="font-bold ${senderClass}">${message.sender_name}:</span> <span class="text-gray-200">${message.content}</span>`; messagesDiv.appendChild(msgEl); messagesDiv.scrollTop = messagesDiv.scrollHeight; }
        async function handleUpdateProfile(e) { e.preventDefault(); const result = await apiCall('/api/profile', { method: 'PUT', body: Object.fromEntries(new FormData(e.target)) }); if (result.success) { appState.currentUser.profile = result.profile; showToast('Profile updated!', 'success'); } }
        async function handleUpgrade(e) { const priceId = e.target.dataset.priceId; const result = await apiCall('/api/create-checkout-session', { method: 'POST', body: { price_id: priceId } }); if (result.success && result.sessionId) { const stripe = Stripe(appState.stripePublicKey); stripe.redirectToCheckout({ sessionId: result.sessionId }); } }
        async function handleManageBilling() { const result = await apiCall('/api/create-customer-portal-session', { method: 'POST' }); if (result.success && result.url) window.location.href = result.url; }
        function handleCreateAssignment() { const content = `<h3 class="text-2xl font-bold text-white mb-4">New Assignment</h3><form id="new-assignment-form"><div class="mb-4"><label class="block text-sm">Title</label><input type="text" name="title" class="w-full p-2 bg-gray-800 rounded" required></div><div class="mb-4"><label class="block text-sm">Description</label><textarea name="description" class="w-full p-2 bg-gray-800 rounded" rows="5" required></textarea></div><div class="mb-4"><label class="block text-sm">Due Date</label><input type="datetime-local" name="due_date" class="w-full p-2 bg-gray-800 rounded" required></div><button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg">Create</button></form>`; showModal(content, (modal) => { modal.querySelector('#new-assignment-form').addEventListener('submit', async (e) => { e.preventDefault(); const formData = Object.fromEntries(new FormData(e.target)); const result = await apiCall(`/api/classes/${appState.selectedClass.id}/assignments`, { method: 'POST', body: formData }); if (result.success) { hideModal(); showToast('Assignment created!', 'success'); switchClassView('assignments'); } }); }); }
        async function viewAssignmentDetails(assignmentId) { const result = await apiCall(`/api/assignments/${assignmentId}`); if(!result.success) return; const assignment = result.assignment; let modalContent = `<h3 class="text-2xl font-bold text-white mb-2">${assignment.title}</h3><p class="text-gray-400 mb-4">${assignment.description}</p><p class="text-sm text-gray-500 mb-6">Due: ${new Date(assignment.due_date).toLocaleString()}</p>`; if(appState.currentUser.role === 'teacher') { modalContent += `<h4 class="text-lg font-semibold text-white mb-2">Submissions</h4>`; if(assignment.submissions.length === 0) modalContent += `<p class="text-gray-400">No submissions yet.</p>`; else modalContent += assignment.submissions.map(s => `<div class="p-2 bg-gray-800 rounded mb-2"><strong>${s.student_name}:</strong> ${s.content.substring(0, 50)}... Grade: ${s.grade || 'Not graded'}</div>`).join(''); } else { if(assignment.my_submission) { modalContent += `<h4 class="text-lg font-semibold text-white mb-2">Your Submission</h4><div class="p-4 bg-gray-800 rounded"><p class="whitespace-pre-wrap">${assignment.my_submission.content}</p><hr class="my-2 border-gray-600"><p><strong>Grade:</strong> ${assignment.my_submission.grade || 'Not graded'}</p><p><strong>Feedback:</strong> ${assignment.my_submission.feedback || 'No feedback yet.'}</p></div>`; } else { modalContent += `<h4 class="text-lg font-semibold text-white mb-2">Submit Your Work</h4><form id="submit-assignment-form"><textarea name="content" class="w-full p-2 bg-gray-800 rounded" rows="8" required></textarea><button type="submit" class="mt-4 bg-green-600 hover:bg-green-500 text-white font-bold py-2 px-4 rounded-lg">Submit</button></form>`; } } showModal(modalContent, modal => { if(modal.querySelector('#submit-assignment-form')) { modal.querySelector('#submit-assignment-form').addEventListener('submit', async e => { e.preventDefault(); const result = await apiCall(`/api/assignments/${assignmentId}/submissions`, { method: 'POST', body: Object.fromEntries(new FormData(e.target)) }); if(result.success) { hideModal(); showToast('Assignment submitted!', 'success'); switchClassView('assignments'); } }); } }); }
        function handleCreateQuiz() { let questionCounter = 0; const content = `<h3 class="text-2xl font-bold text-white mb-4">New Quiz</h3><form id="new-quiz-form"><div class="mb-4"><label class="block text-sm">Title</label><input type="text" name="title" class="w-full p-2 bg-gray-800 rounded" required></div><div class="mb-4"><label class="block text-sm">Description</label><textarea name="description" class="w-full p-2 bg-gray-800 rounded" rows="3"></textarea></div><div class="mb-4"><label class="block text-sm">Time Limit (minutes)</label><input type="number" name="time_limit" class="w-full p-2 bg-gray-800 rounded" required min="1"></div><hr class="my-4 border-gray-600"><div id="questions-container"></div><button type="button" id="add-question-btn" class="text-sm text-blue-400 hover:text-blue-300">+ Add Question</button><hr class="my-4 border-gray-600"><button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white font-bold py-2 px-4 rounded-lg">Create Quiz</button></form>`; showModal(content, modal => { const addQuestion = () => { const qId = questionCounter++; const qContainer = document.createElement('div'); qContainer.className = 'p-4 border border-gray-700 rounded-lg mb-4'; qContainer.innerHTML = `<div class="flex justify-between items-center mb-2"><label class="block text-sm">Question ${qId + 1}</label><button type="button" class="text-red-500 text-xs remove-question-btn">Remove</button></div><textarea name="q-text-${qId}" class="w-full p-2 bg-gray-700 rounded" required></textarea><div class="mt-2"><label class="block text-sm">Type</label><select name="q-type-${qId}" class="w-full p-2 bg-gray-700 rounded q-type-select"><option value="multiple_choice">Multiple Choice</option></select></div><div class="choices-container mt-2"></div>`; document.getElementById('questions-container').appendChild(qContainer); qContainer.querySelector('.remove-question-btn').addEventListener('click', () => qContainer.remove()); qContainer.querySelector('.q-type-select').dispatchEvent(new Event('change')); }; modal.querySelector('#add-question-btn').addEventListener('click', addQuestion); modal.querySelector('#questions-container').addEventListener('change', e => { if(e.target.classList.contains('q-type-select')) { const choicesContainer = e.target.closest('.p-4').querySelector('.choices-container'); const qId = e.target.name.split('-')[2]; choicesContainer.innerHTML = `<div class="space-y-2"><div class="flex items-center gap-2"><input type="radio" name="q-correct-${qId}" value="0" required><input type="text" name="q-choice-${qId}-0" class="flex-grow p-1 bg-gray-600 rounded" placeholder="Choice 1" required></div><div class="flex items-center gap-2"><input type="radio" name="q-correct-${qId}" value="1"><input type="text" name="q-choice-${qId}-1" class="flex-grow p-1 bg-gray-600 rounded" placeholder="Choice 2" required></div><div class="flex items-center gap-2"><input type="radio" name="q-correct-${qId}" value="2"><input type="text" name="q-choice-${qId}-2" class="flex-grow p-1 bg-gray-600 rounded" placeholder="Choice 3"></div><div class="flex items-center gap-2"><input type="radio" name="q-correct-${qId}" value="3"><input type="text" name="q-choice-${qId}-3" class="flex-grow p-1 bg-gray-600 rounded" placeholder="Choice 4"></div></div>`; } }); modal.querySelector('#new-quiz-form').addEventListener('submit', async e => { e.preventDefault(); const form = e.target; const quizData = { title: form.title.value, description: form.description.value, time_limit: form.time_limit.value, questions: [] }; document.querySelectorAll('#questions-container > div').forEach((qDiv, i) => { const qId = i; const qText = qDiv.querySelector(`textarea[name="q-text-${qId}"]`).value; const qType = qDiv.querySelector(`select[name="q-type-${qId}"]`).value; const question = { text: qText, type: qType, choices: [] }; if(qType === 'multiple_choice') { const correctIndex = qDiv.querySelector(`input[name="q-correct-${qId}"]:checked`).value; qDiv.querySelectorAll('input[type="text"]').forEach((cInput, cIndex) => { if(cInput.value) question.choices.push({ text: cInput.value, is_correct: cIndex == correctIndex }); }); } quizData.questions.push(question); }); const result = await apiCall(`/api/classes/${appState.selectedClass.id}/quizzes`, { method: 'POST', body: quizData }); if(result.success) { hideModal(); showToast('Quiz created!', 'success'); switchClassView('quizzes'); } }); addQuestion(); }); }
        async function viewQuizDetails(quizId) { const result = await apiCall(`/api/quizzes/${quizId}`); if(!result.success) return; const quiz = result.quiz; if(appState.currentUser.role === 'teacher') { let modalContent = `<h3 class="text-2xl font-bold text-white mb-2">${quiz.title}</h3><p class="text-gray-400 mb-4">${quiz.description}</p><h4 class="text-lg font-semibold text-white mb-2">Attempts</h4>`; if(quiz.attempts.length === 0) modalContent += `<p class="text-gray-400">No attempts yet.</p>`; else modalContent += `<div class="overflow-x-auto"><table class="w-full text-left"><thead><tr><th>Student</th><th>Score</th><th>Submitted</th></tr></thead><tbody>${quiz.attempts.map(a => `<tr><td>${a.student_name}</td><td>${a.score.toFixed(2)}%</td><td>${new Date(a.end_time).toLocaleString()}</td></tr>`).join('')}</tbody></table></div>`; showModal(modalContent); } else { const studentAttempt = quiz.student_attempt; if(studentAttempt) { showModal(`<h3 class="text-2xl font-bold text-white mb-2">Quiz Results: ${quiz.title}</h3><p class="text-4xl font-bold text-center my-8">${studentAttempt.score.toFixed(2)}%</p><p class="text-center text-gray-400">You have already completed this quiz.</p>`); } else { if(confirm(`Start quiz: ${quiz.title}?\\nYou will have ${quiz.time_limit} minutes.`)) startQuiz(quizId); } } }
        async function startQuiz(quizId) { const result = await apiCall(`/api/quizzes/${quizId}/start`, { method: 'POST' }); if(!result.success) return; const { attempt_id, questions, time_limit, start_time } = result; let currentQuestionIndex = 0; const userAnswers = {}; const deadline = new Date(new Date(start_time).getTime() + time_limit * 60000); const renderQuestion = () => { const q = questions[currentQuestionIndex]; let choicesHtml = ''; if(q.question_type === 'multiple_choice') { choicesHtml = `<div class="space-y-3 mt-4">${q.choices.map(c => `<label class="flex items-center p-3 bg-gray-800 rounded-lg cursor-pointer hover:bg-gray-700"><input type="radio" name="answer" value="${c.id}" class="mr-3"><span class="text-white">${c.text}</span></label>`).join('')}</div>`; } const content = `<div class="flex justify-between items-center"><h3 class="text-2xl font-bold text-white">${appState.selectedClass.name} Quiz</h3><div id="quiz-timer" class="text-xl font-mono text-red-500"></div></div><hr class="my-4 border-gray-600"><p class="text-gray-400 mb-2">Question ${currentQuestionIndex + 1} of ${questions.length}</p><h4 class="text-xl font-semibold text-white">${q.text}</h4>${choicesHtml}<div class="flex justify-between mt-8"><button id="prev-btn" class="bg-gray-600 py-2 px-4 rounded-lg">Previous</button><button id="next-btn" class="bg-blue-600 py-2 px-4 rounded-lg">Next</button></div>`; showModal(content, modal => { if(currentQuestionIndex === 0) modal.querySelector('#prev-btn').style.visibility = 'hidden'; if(currentQuestionIndex === questions.length - 1) { modal.querySelector('#next-btn').textContent = 'Submit'; modal.querySelector('#next-btn').classList.replace('bg-blue-600', 'bg-green-600'); } modal.querySelector('#prev-btn').addEventListener('click', () => { saveAnswer(); currentQuestionIndex--; renderQuestion(); }); modal.querySelector('#next-btn').addEventListener('click', () => { saveAnswer(); if(currentQuestionIndex === questions.length - 1) submitQuiz(attempt_id, userAnswers); else { currentQuestionIndex++; renderQuestion(); } }); if(userAnswers[q.id]) modal.querySelector(`input[value="${userAnswers[q.id]}"]`).checked = true; }, 'max-w-4xl'); }; const saveAnswer = () => { const selected = document.querySelector('input[name="answer"]:checked'); if(selected) userAnswers[questions[currentQuestionIndex].id] = selected.value; }; const updateTimer = () => { const now = new Date(); const diff = deadline - now; if(diff <= 0) { clearInterval(appState.quizTimer); submitQuiz(attempt_id, userAnswers); } else { const minutes = Math.floor(diff / 60000); const seconds = Math.floor((diff % 60000) / 1000); document.getElementById('quiz-timer').textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`; } }; if(appState.quizTimer) clearInterval(appState.quizTimer); appState.quizTimer = setInterval(updateTimer, 1000); renderQuestion(); }
        async function submitQuiz(attempt_id, answers) { if(appState.quizTimer) clearInterval(appState.quizTimer); const result = await apiCall(`/api/attempts/${attempt_id}/submit`, { method: 'POST', body: { answers } }); if(result.success) { showModal(`<h3 class="text-2xl font-bold text-white mb-2">Quiz Submitted!</h3><p class="text-4xl font-bold text-center my-8">${result.attempt.score.toFixed(2)}%</p><p class="text-center text-gray-400">Your results have been saved.</p>`); switchClassView('quizzes'); } }
        function handleAdminUserAction(action, userId) { if(action === 'delete') { if(confirm('Are you sure you want to delete this user? This is irreversible.')) { apiCall(`/api/admin/user/${userId}`, { method: 'DELETE' }).then(res => { if(res.success) { showToast(res.message, 'success'); switchAdminView('users'); } }); } } }
        function handleAdminDeleteClass(classId) { if(confirm('Are you sure you want to delete this class? This will delete all associated data.')) { apiCall(`/api/admin/class/${classId}`, { method: 'DELETE' }).then(res => { if(res.success) { showToast(res.message, 'success'); switchAdminView('classes'); } }); } }
        async function handleAdminUpdateSettings(e) { e.preventDefault(); const result = await apiCall('/api/admin/update_settings', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) }); if(result.success) showToast(result.message, 'success'); }
        async function setupNotificationBell() { const container = document.getElementById('notification-bell-container'); container.innerHTML = `<button id="notification-bell" class="relative text-gray-400 hover:text-white"><svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" /></svg><div id="notification-dot" class="hidden absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full"></div></button><div id="notification-panel" class="hidden absolute bottom-full right-0 w-80 bg-gray-800 rounded-lg shadow-lg mb-2 z-50"></div>`; document.getElementById('notification-bell').addEventListener('click', toggleNotificationPanel); const result = await apiCall('/api/notifications'); if(result.success && result.notifications.some(n => !n.is_read)) updateNotificationBell(true); }
        function updateNotificationBell(hasUnread) { const dot = document.getElementById('notification-dot'); if(dot) dot.classList.toggle('hidden', !hasUnread); }
        async function toggleNotificationPanel() { const panel = document.getElementById('notification-panel'); if(panel.classList.toggle('hidden')) return; panel.innerHTML = `<div class="p-4"><div class="loader mx-auto"></div></div>`; const result = await apiCall('/api/notifications'); if(result.success) { if(result.notifications.length === 0) panel.innerHTML = `<div class="p-4 text-center text-gray-400">No notifications.</div>`; else panel.innerHTML = result.notifications.map(n => `<div class="p-3 border-b border-gray-700 ${n.is_read ? 'opacity-50' : ''}"><p class="text-sm">${n.content}</p><p class="text-xs text-gray-500">${new Date(n.timestamp).toLocaleString()}</p></div>`).join(''); const unreadIds = result.notifications.filter(n => !n.is_read).map(n => n.id); if(unreadIds.length > 0) { await apiCall('/api/notifications/mark_read', { method: 'POST', body: { ids: unreadIds }}); updateNotificationBell(false); } } }
        function initializeApp(user, settings) { appState.currentUser = user; appState.stripePublicKey = settings.STRIPE_PUBLIC_KEY; if (settings && settings.announcement) { DOMElements.announcementBanner.textContent = settings.announcement; DOMElements.announcementBanner.classList.remove('hidden'); } setupDashboard(); }
        async function main() { const result = await apiCall('/api/status'); if (result.success && result.logged_in) initializeApp(result.user, result.settings); else setupAuthPage(); }
        main();
    });
    </script>
</body>
</html>
"""
# ==============================================================================
# --- 16. APP INITIALIZATION & EXECUTION ---
# ==============================================================================
def initialize_app_database():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(role='admin').first():
            admin_pass = os.environ.get('ADMIN_PASSWORD', 'change-this-default-password')
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
            admin = User(username='admin', email=admin_email, password_hash=generate_password_hash(admin_pass), role='admin', plan='admin')
            db.session.add(admin)
            logging.info(f"Created default admin user with email {admin_email}.")
        if not SiteSettings.query.get('announcement'):
            db.session.add(SiteSettings(key='announcement', value='Welcome to the new Myth AI Portal!'))
            logging.info("Created default site announcement.")
        db.session.commit()
if __name__ == '__main__':
    initialize_app_database()
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
