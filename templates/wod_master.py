import os
import json
import time
import io
from datetime import datetime
from dotenv import load_dotenv 
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai
import stripe
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from fpdf import FPDF 

# ==========================================
# 1. CONFIGURACIÓN
# ==========================================
load_dotenv() 

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'clave-por-defecto-insegura')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# STRIPE
stripe.api_key = os.getenv('STRIPE_SECRET_KEY') 
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
STRIPE_PRICE_ID = os.getenv('STRIPE_PRICE_ID')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET') 

# MAIL
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

# GEMINI
MI_CLAVE_API = os.getenv('GEMINI_API_KEY')
try:
    genai.configure(api_key=MI_CLAVE_API)
    model = genai.GenerativeModel('gemini-2.0-flash') 
except Exception as e:
    print(f"Error configurando Gemini API: {e}")

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)
s = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))

# ==========================================
# 2. MODELOS
# ==========================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    gym_name = db.Column(db.String(80), nullable=False)
    credits = db.Column(db.Integer, default=3)
    is_premium = db.Column(db.Boolean, default=False)
    stripe_customer_id = db.Column(db.String(100), nullable=True)
    ai_uses_count = db.Column(db.Integer, default=0) 
    wods = db.relationship('Wod', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Wod(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    tone = db.Column(db.String(50), nullable=False)
    target_audience = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    structure = db.Column(db.Text, nullable=False)
    objective = db.Column(db.String(255), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    
    ai_strategy = db.Column(db.Text, nullable=True)
    ai_warmup = db.Column(db.Text, nullable=True)
    ai_instagram_post = db.Column(db.Text, nullable=True)
    ai_newsletter_text = db.Column(db.Text, nullable=True)
    ai_reel_script = db.Column(db.Text, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==========================================
# 3. LÓGICA IA
# ==========================================
def generar_contenido_ai(wod):
    prompt = f"""
    Actúa como Head Coach experto. 
    WOD: {wod.title} ({wod.category}). Estructura: {wod.structure}. Objetivo: {wod.objective}. Tono: {wod.tone}. Público: {wod.target_audience}.
    Genera JSON con estas claves exactas:
    {{
        "strategy": "Estrategia y escalados.",
        "warmup": "Calentamiento específico.",
        "instagram_post": "Texto para post con hashtags.",
        "newsletter_text": "Email para socios motivador.",
        "reel_script": "Guion viral para vídeo corto."
    }}
    """
    try:
        response = model.generate_content(prompt)
        clean_text = response.text.strip()
        if clean_text.startswith("```json"):
            clean_text = clean_text.strip("```json").strip("```").strip()
        elif clean_text.startswith("{") and clean_text.endswith("}"):
            pass
        
        data = json.loads(clean_text)
        
        wod.ai_strategy = data.get('strategy', 'No disponible')
        wod.ai_warmup = data.get('warmup', 'No disponible')
        wod.ai_instagram_post = data.get('instagram_post', 'No disponible')
        wod.ai_newsletter_text = data.get('newsletter_text', 'No disponible')
        wod.ai_reel_script = data.get('reel_script', 'No disponible')
        return True
    except Exception as e:
        print(f"Error IA: {e}")
        return False

# ==========================================
# 4. RUTAS PRINCIPALES
# ==========================================
@app.route('/')
def root(): 
    if not current_user.is_authenticated:
        return redirect(url_for('landing'))
    return redirect(url_for('index'))

@app.route('/landing')
def landing():
    if current_user.is_authenticated: return redirect(url_for('index'))
    return render_template('landing.html')

@app.route('/index')
@login_required
def index():
    wods = Wod.query.filter_by(user_id=current_user.id).order_by(Wod.date.desc()).all()
    return render_template('index.html', wods=wods, user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        gym_name = request.form.get('gym_name')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash('Email ya registrado.', 'error')
            return redirect(url_for('register'))
        
        token_data = {'email': email, 'gym': gym_name, 'password': generate_password_hash(password)}
        token = s.dumps(token_data, salt='email-confirm')
        
        confirmation_url = url_for('confirm_email', token=token, _external=True)
        
        try:
            msg = Message('¡Confirma tu Email para WOD Master PRO! ✉️', 
                          sender=app.config['MAIL_USERNAME'], 
                          recipients=[email])
            msg.body = f"""Hola {gym_name},

Para completar tu registro y acceder a WOD Master PRO, haz clic en el siguiente enlace:

{confirmation_url}

Si no has solicitado este registro, ignora este correo.
El equipo de WOD Master."""
            mail.send(msg)
            
            flash('✅ Se ha enviado un email de verificación. Revisa tu bandeja de entrada para activar tu cuenta.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error al enviar el email de verificación: {e}', 'error')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    try:
        token_data = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        flash('❌ El enlace de confirmación no es válido o ha caducado. Regístrate de nuevo.', 'error')
        return redirect(url_for('register'))

    email = token_data['email']
    
    if User.query.filter_by(email=email).first():
        flash('Tu cuenta ya está activa. Por favor, inicia sesión.', 'success')
        return redirect(url_for('login'))
        
    new_user = User(
        email=email,
        password_hash=token_data['password'],
        gym_name=token_data['gym'],
        credits=3,
        is_premium=False
    )
    db.session.add(new_user)
    db.session.commit()
    
    login_user(new_user)
    flash('🎉 ¡Cuenta activada con éxito! Bienvenido a WOD Master PRO.', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash('Datos incorrectos', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('root'))

# --- RUTAS LEGALES ---
@app.route('/privacy')
def privacy(): return render_template('privacy.html')
@app.route('/terms')
def terms(): return render_template('terms.html')
@app.route('/contact')
def contact(): return render_template('contact.html')

# --- GESTIÓN DE WODS ---
@app.route('/add_wod', methods=['GET', 'POST'])
@login_required
def add_wod():
    if request.method == 'POST':
        try:
            nw = Wod(
                user_id=current_user.id,
                date=datetime.strptime(request.form.get('date'), '%Y-%m-%d').date(),
                title=request.form.get('title'),
                category=request.form.get('category'),
                structure=request.form.get('structure'),
                objective=request.form.get('objective'),
                notes=request.form.get('notes'),
                tone=request.form.get('tone'),
                target_audience=request.form.get('target_audience')
            )
            db.session.add(nw)
            db.session.commit()
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error: {e}', 'error')
    return render_template('add_wod.html')

@app.route('/edit_wod/<int:wod_id>', methods=['GET', 'POST'])
@login_required
def edit_wod(wod_id):
    wod = Wod.query.filter_by(id=wod_id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        wod.title = request.form.get('title')
        wod.structure = request.form.get('structure')
        wod.objective = request.form.get('objective')
        wod.notes = request.form.get('notes')
        wod.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        wod.category = request.form.get('category')
        wod.tone = request.form.get('tone')
        wod.target_audience = request.form.get('target_audience')
        db.session.commit()
        return redirect(url_for('index'))
    wod_date_str = wod.date.isoformat() if wod.date else None
    return render_template('edit_wod.html', wod=wod, wod_date_str=wod_date_str)

@app.route('/delete_wod/<int:wod_id>', methods=['POST'])
@login_required
def delete_wod(wod_id):
    wod = Wod.query.filter_by(id=wod_id, user_id=current_user.id).first_or_404()
    db.session.delete(wod)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/generate_ai_content/<int:wod_id>', methods=['POST'])
@login_required
def generate_ai_content(wod_id):
    wod = Wod.query.filter_by(id=wod_id, user_id=current_user.id).first_or_404()
    if not current_user.is_premium and current_user.credits <= 0:
        flash('Sin créditos. Pásate a PRO.', 'error')
        return redirect(url_for('index'))
    
    if generar_contenido_ai(wod):
        if not current_user.is_premium: current_user.credits -= 1
        if current_user.ai_uses_count is None: current_user.ai_uses_count = 0
        current_user.ai_uses_count += 1
        db.session.commit()
        flash('Contenido generado.', 'success')
    else:
        flash('Error IA.', 'error')
    return redirect(url_for('index'))

@app.route('/export_pdf/<int:wod_id>')
@login_required
def export_pdf(wod_id):
    wod = Wod.query.filter_by(id=wod_id, user_id=current_user.id).first_or_404()

    class PDF(FPDF):
        def header(self):
            # Franja azul superior
            self.set_fill_color(41, 121, 255) # Azul corporativo
            self.rect(0, 0, 210, 40, 'F')
            
            # Nombre del Gimnasio
            self.set_font('Arial', 'B', 24)
            self.set_text_color(255, 255, 255) # Blanco
            self.set_y(10)
            gym_name = wod.user.gym_name.upper().encode('latin-1', 'replace').decode('latin-1')
            self.cell(0, 10, gym_name, 0, 1, 'C')
            
            # Subtítulo
            self.set_font('Arial', 'I', 12)
            self.cell(0, 10, 'Programacion Profesional', 0, 1, 'C')
            self.ln(20)

        def footer(self):
            self.set_y(-15)
            self.set_font('Arial', 'I', 8)
            self.set_text_color(128)
            self.cell(0, 10, f'Pagina {self.page_no()}/{{nb}} | WOD Master PRO', 0, 0, 'C')

        def chapter_title(self, label):
            # Título de sección con fondo gris claro/azul
            self.set_font('Arial', 'B', 12)
            self.set_text_color(41, 121, 255)
            self.set_fill_color(240, 248, 255) # Azul muy claro
            self.cell(0, 10, f"  {label}", 0, 1, 'L', 1)
            self.ln(4)

        def chapter_body(self, body):
            self.set_font('Arial', '', 11)
            self.set_text_color(0)
            # Limpieza de caracteres para evitar errores de codificación en PDF
            safe_body = body.encode('latin-1', 'replace').decode('latin-1')
            self.multi_cell(0, 6, safe_body)
            self.ln(5)

    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Título del WOD
    pdf.set_font('Arial', 'B', 20)
    pdf.set_text_color(0)
    safe_title = wod.title.encode('latin-1', 'replace').decode('latin-1')
    pdf.cell(0, 10, safe_title, 0, 1, 'C')
    
    # Barra de Metadatos (Gris)
    pdf.set_fill_color(245, 245, 245)
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(80)
    date_str = wod.date.strftime('%d/%m/%Y')
    meta_text = f"FECHA: {date_str}  |  CATEGORIA: {wod.category}  |  TONO: {wod.tone}"
    safe_meta = meta_text.encode('latin-1', 'replace').decode('latin-1')
    pdf.cell(0, 8, safe_meta, 0, 1, 'C', 1)
    pdf.ln(10)

    # Secciones
    pdf.chapter_title("ESTRUCTURA DEL ENTRENAMIENTO")
    pdf.chapter_body(wod.structure)

    if wod.objective:
        pdf.chapter_title("OBJETIVO DEL ESTIMULO")
        pdf.chapter_body(wod.objective)

    if wod.ai_warmup:
        pdf.chapter_title("CALENTAMIENTO (WARM-UP)")
        pdf.chapter_body(wod.ai_warmup)

    if wod.ai_strategy:
        pdf.chapter_title("ESTRATEGIA Y ESCALADOS")
        pdf.chapter_body(wod.ai_strategy)
        
    if wod.notes:
        pdf.chapter_title("NOTAS ADICIONALES")
        pdf.chapter_body(wod.notes)

    # Generar
    buffer = io.BytesIO()
    pdf_output = pdf.output(dest='S').encode('latin-1')
    buffer.write(pdf_output)
    buffer.seek(0)
    
    return send_file(buffer, as_attachment=True, download_name=f"WOD_{wod.date.strftime('%Y%m%d')}.pdf", mimetype='application/pdf')

# --- FUNCIÓN CORREGIDA DE BORRADO DE CUENTA ---
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    # 1. Capturar el objeto usuario antes de hacer logout
    user_to_delete = current_user
    
    try:
        # 2. Borrar todos los WODs asociados a este usuario
        Wod.query.filter_by(user_id=user_to_delete.id).delete()
        
        # 3. Borrar el usuario
        db.session.delete(user_to_delete)
        db.session.commit()
        
        # 4. Cerrar sesión al final
        logout_user()
        
        flash('Tu cuenta ha sido eliminada permanentemente. ¡Adiós! 😢', 'success')
        return redirect(url_for('root'))
        
    except Exception as e:
        db.session.rollback()
        flash('Error al eliminar la cuenta. Inténtalo de nuevo.', 'error')
        return redirect(url_for('index'))

# --- PAGOS Y ADMIN ---
@app.route('/pricing')
def pricing(): return render_template('pricing.html', STRIPE_PUBLISHABLE_KEY=STRIPE_PUBLISHABLE_KEY, STRIPE_PRICE_ID=STRIPE_PRICE_ID)

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    session = stripe.checkout.Session.create(
        line_items=[{'price': STRIPE_PRICE_ID, 'quantity': 1}],
        mode='subscription',
        success_url=url_for('success', _external=True),
        cancel_url=url_for('pricing', _external=True),
        client_reference_id=str(current_user.id)
    )
    return redirect(session.url, code=303)

@app.route('/billing')
@login_required
def billing():
    if not current_user.stripe_customer_id: return redirect(url_for('pricing'))
    session = stripe.billing_portal.Session.create(
        customer=current_user.stripe_customer_id, return_url=url_for('index', _external=True))
    return redirect(session.url)

@app.route('/success')
@login_required
def success():
    current_user.is_premium = True
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
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

@app.route('/super_admin')
@login_required
def super_admin():
    if current_user.email != "pau.garcia.ru@gmail.com": abort(403)
    return render_template('admin_dashboard.html', users=User.query.all())

# --- PASSWORD RESET ---
@app.route('/reset_password_request', methods=['GET', 'POST']) 
def reset_request():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user:
            token = s.dumps(user.email, salt='recuperar')
            link = url_for('reset_token', token=token, _external=True)
            mail.send(Message('Reset Password', sender=app.config['MAIL_USERNAME'], recipients=[user.email], body=f'Link: {link}'))
            flash('Correo enviado', 'success')
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try: email = s.loads(token, salt='recuperar', max_age=3600)
    except: return redirect(url_for('reset_request'))
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        user.set_password(request.form.get('password'))
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('reset_token.html')

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True)