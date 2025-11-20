import os
import json
import time
from datetime import datetime
from dotenv import load_dotenv 
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # <--- NUEVO
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai
import stripe
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

# ==========================================
# 1. CARGA DE SECRETOS
# ==========================================
load_dotenv() 

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'clave-por-defecto-insegura')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CONFIGURACIÓN STRIPE 
stripe.api_key = os.getenv('STRIPE_SECRET_KEY') 
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
STRIPE_PRICE_ID = os.getenv('STRIPE_PRICE_ID')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET') 

# CONFIGURACIÓN FLASK-MAIL
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY']) 

# GOOGLE GEMINI API
MI_CLAVE_API = os.getenv('GEMINI_API_KEY')
try:
    genai.configure(api_key=MI_CLAVE_API)
except Exception as e:
    print(f"Error clave IA: {e}")

# INICIALIZACIÓN DB, MIGRATE Y LOGIN
db = SQLAlchemy(app)
migrate = Migrate(app, db) # <--- INICIALIZACIÓN MIGRATE
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ==========================================
# 2. MODELOS BBDD 
# ==========================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    gym_name = db.Column(db.String(100), nullable=False)
    
    credits = db.Column(db.Integer, default=3) 
    is_premium = db.Column(db.Boolean, default=False) 
    stripe_customer_id = db.Column(db.String(100), nullable=True) 
    
    # NUEVO CAMPO: ESTADÍSTICAS DE USO
    ai_uses_count = db.Column(db.Integer, default=0)

    wods = db.relationship('Wod', backref='owner', lazy=True)

class Wod(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), default='General', nullable=False)
    structure = db.Column(db.Text, nullable=False)
    objective = db.Column(db.String(200), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    tone = db.Column(db.String(50), default='Motivador', nullable=False)
    target_audience = db.Column(db.String(50), default='General', nullable=False)
    
    ai_instagram_post = db.Column(db.Text, nullable=True)
    ai_newsletter_text = db.Column(db.Text, nullable=True)
    ai_reel_script = db.Column(db.Text, nullable=True)
    ai_warmup = db.Column(db.Text, nullable=True)
    ai_strategy = db.Column(db.Text, nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==========================================
# 3. LÓGICA IA 
# ==========================================
def generar_contenido_ia(wod_data):
    descripcion = (
        f"Fecha: {wod_data['date'].strftime('%d-%m-%Y')}\n"
        f"Título: {wod_data['title']}\n"
        f"Categoría: {wod_data['category']}\n"
        f"Estructura: {wod_data['structure']}\n"
        f"Objetivo: {wod_data['objective']}\n"
        f"Público: {wod_data.get('target_audience', 'General')}"
    )
    
    prompt = f"""
    Actúa como Head Coach experto. Tono: {wod_data.get('tone')}.
    WOD: {descripcion}
    Genera JSON válido con 5 claves:
    1. "post_instagram": Texto marketing.
    2. "newsletter_texto": Email socios.
    3. "guion_reel": Guion video.
    4. "warmup": Calentamiento.
    5. "estrategia_escalados": Estrategia y versiones.
    """
    
    modelos = ['gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-1.5-pro']
    for modelo in modelos:
        try:
            ai = genai.GenerativeModel(modelo)
            res = ai.generate_content(prompt)
            txt = res.text.strip()
            if txt.startswith("```json"): txt = txt[7:]
            if txt.startswith("```"): txt = txt[3:]
            if txt.endswith("```"): txt = txt[:-3]
            return json.loads(txt)
        except Exception:
            continue
    return None

# ==========================================
# 4. RUTAS APP 
# ==========================================
@app.route('/')
@login_required
def index():
    wods = Wod.query.filter_by(user_id=current_user.id).order_by(Wod.date.desc()).all()
    return render_template('index.html', wods=wods, user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form.get('email')).first():
            flash('Email ya registrado', 'error')
            return redirect(url_for('register'))
        
        new_user = User(
            email=request.form.get('email'),
            password=generate_password_hash(request.form.get('password')),
            gym_name=request.form.get('gym_name'),
            credits=3,
            is_premium=False
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash('Credenciales incorrectas', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- RUTAS LEGALES ---
@app.route('/privacy')
def privacy(): return render_template('privacy.html')

@app.route('/terms')
def terms(): return render_template('terms.html')

# --- RUTAS PASSWORD ---
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.email, salt='recuperar-clave')
            link = url_for('reset_token', token=token, _external=True)
            msg = Message('Recuperar Contraseña', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
            msg.body = f'Click aquí: {link}'
            try:
                mail.send(msg)
                flash('Email enviado.', 'success')
            except Exception as e:
                flash(f'Error: {e}', 'error')
            return redirect(url_for('login'))
        else:
            flash('Email no encontrado.', 'error')
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated: return redirect(url_for('index'))
    try: email = s.loads(token, salt='recuperar-clave', max_age=3600)
    except: return redirect(url_for('reset_request'))
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(request.form.get('password'))
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('reset_token.html')

# --- CRUD WODS ---
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_wod():
    if request.method == 'POST':
        try:
            nuevo = Wod(
                user_id=current_user.id,
                date=datetime.strptime(request.form['date'], '%Y-%m-%d').date(),
                title=request.form['title'],
                category=request.form['category'],
                structure=request.form['structure'],
                objective=request.form['objective'],
                notes=request.form['notes'],
                tone=request.form['tone'],
                target_audience=request.form['target_audience']
            )
            db.session.add(nuevo)
            db.session.commit()
            return redirect(url_for('index'))
        except Exception as e:
            flash(str(e), 'error')
    return render_template('add_wod.html')

@app.route('/edit/<int:wod_id>', methods=['GET', 'POST'])
@login_required
def edit_wod(wod_id):
    wod = Wod.query.filter_by(id=wod_id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        wod.date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        wod.title = request.form['title']
        wod.category = request.form['category']
        wod.structure = request.form['structure']
        wod.objective = request.form['objective']
        wod.notes = request.form['notes']
        wod.tone = request.form['tone']
        wod.target_audience = request.form['target_audience']
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit_wod.html', wod=wod)

@app.route('/delete/<int:wod_id>', methods=['POST'])
@login_required
def delete_wod(wod_id):
    wod = Wod.query.filter_by(id=wod_id, user_id=current_user.id).first_or_404()
    db.session.delete(wod)
    db.session.commit()
    return redirect(url_for('index'))

# ==========================================
# 5. IA + ESTADÍSTICAS
# ==========================================
@app.route('/generate_ai/<int:wod_id>', methods=['POST'])
@login_required
def generate_ai_content(wod_id):
    wod = Wod.query.filter_by(id=wod_id, user_id=current_user.id).first_or_404()
    
    if not current_user.is_premium and current_user.credits <= 0:
        flash('🔒 Se acabaron tus créditos gratuitos. Pásate a PRO.', 'error')
        return redirect(url_for('pricing'))

    contenido = generar_contenido_ia({
        'date': wod.date, 'title': wod.title, 'category': wod.category,
        'structure': wod.structure, 'objective': wod.objective,
        'notes': wod.notes, 'tone': wod.tone, 
        'target_audience': wod.target_audience
    })

    if contenido:
        def safe(d): return json.dumps(d, indent=2, ensure_ascii=False) if isinstance(d, (dict, list)) else str(d) if d else ""
        wod.ai_instagram_post = safe(contenido.get('post_instagram'))
        wod.ai_newsletter_text = safe(contenido.get('newsletter_texto'))
        wod.ai_reel_script = safe(contenido.get('guion_reel'))
        wod.ai_warmup = safe(contenido.get('warmup'))
        wod.ai_strategy = safe(contenido.get('estrategia_escalados'))
        
        # ACTUALIZACIÓN DE CRÉDITOS Y ESTADÍSTICAS
        if not current_user.is_premium:
            current_user.credits -= 1
        
        # NUEVO: CONTAR USO DE IA
        if current_user.ai_uses_count is None: current_user.ai_uses_count = 0
        current_user.ai_uses_count += 1
        
        db.session.commit()
        flash('✨ Contenido generado correctamente.', 'success')
    else:
        flash('Error en la IA. Intenta de nuevo.', 'error')
        
    return redirect(url_for('index'))

# ==========================================
# 6. FACTURACIÓN Y ADMIN
# ==========================================
@app.route('/pricing')
@login_required
def pricing():
    return render_template('pricing.html', key=STRIPE_PUBLISHABLE_KEY)

# NUEVA RUTA: PORTAL DE CLIENTE STRIPE
@app.route('/billing')
@login_required
def billing():
    if not current_user.stripe_customer_id:
        flash('No tienes historial de facturación aún.', 'error')
        return redirect(url_for('index'))
        
    session = stripe.billing_portal.Session.create(
        customer=current_user.stripe_customer_id,
        return_url=url_for('index', _external=True)
    )
    return redirect(session.url)

# NUEVA RUTA: DASHBOARD ADMIN (SOLO PARA TI)
@app.route('/super_admin')
@login_required
def super_admin():
    # CAMBIA ESTO POR TU EMAIL REAL PARA PROTEGER LA RUTA
    if current_user.email != "pau.garcia.ru@gmail.com": 
        abort(403) # Prohibido para otros
        
    users = User.query.all()
    total_users = len(users)
    total_premium = sum(1 for u in users if u.is_premium)
    
    return render_template('admin_dashboard.html', users=users, total=total_users, premium=total_premium)

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    try:
        checkout_session = stripe.checkout.Session.create(
            client_reference_id=current_user.id,
            customer=current_user.stripe_customer_id if current_user.stripe_customer_id else None, # Reusar cliente si existe
            line_items=[{'price': STRIPE_PRICE_ID, 'quantity': 1}],
            mode='subscription',
            success_url=url_for('success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('pricing', _external=True),
        )
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        return str(e)

@app.route('/success')
@login_required
def success():
    user = User.query.get(current_user.id)
    if user:
        user.is_premium = True 
        user.credits = 99999 
        db.session.commit()
    logout_user()
    login_user(user)
    flash('🚀 ¡Bienvenido a PRO!', 'success')
    return redirect(url_for('index'))

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    event = None
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError as e: return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e: return 'Invalid signature', 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('client_reference_id')
        stripe_customer_id = session.get('customer')
        if user_id:
            with app.app_context(): 
                user = User.query.get(user_id)
                if user:
                    user.is_premium = True
                    user.credits = 999999 
                    user.stripe_customer_id = stripe_customer_id
                    db.session.commit()
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        stripe_customer_id = subscription.get('customer')
        with app.app_context():
            user = User.query.filter_by(stripe_customer_id=stripe_customer_id).first()
            if user:
                user.is_premium = False
                user.credits = 0 
                db.session.commit()
    return jsonify(success=True)

if __name__ == '__main__':
    # NOTA: db.create_all() ya no se recomienda al usar Flask-Migrate, 
    # pero lo dejamos por compatibilidad con Render si no ejecutas migraciones.
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)