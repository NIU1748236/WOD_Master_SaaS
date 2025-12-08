import os
import json
import time
import io
import random
from threading import Thread
from datetime import datetime
from dotenv import load_dotenv 
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai
import stripe
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from fpdf import FPDF 
from sqlalchemy import extract

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

# ADMIN EMAIL
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'pau.garcia.ru@gmail.com')

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
# 3. UTILIDADES (Email Async & IA)
# ==========================================
def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            print(f"Error enviando email async: {e}")

def enviar_email_fondo(subject, recipients, body):
    msg = Message(subject, sender=("WOD Master Support", app.config['MAIL_USERNAME']), recipients=recipients)
    msg.body = body
    Thread(target=send_async_email, args=(app, msg)).start()

def generar_contenido_ai(wod):
    prompt = f"""
    Actúa como Head Coach experto y Community Manager de un box de CrossFit.
    WOD: {wod.title} ({wod.category}). 
    Estructura: {wod.structure}. 
    Objetivo: {wod.objective}. 
    Tono: {wod.tone}. 
    Público: {wod.target_audience}.

    IMPORTANTE: No uses formato Markdown (como **negritas** o ## títulos). Usa solo texto plano limpio.
    
    Genera un JSON válido con estas claves exactas (sin texto antes ni después, solo el JSON):
    {{
        "strategy": "Estrategia detallada y opciones de escalado.",
        "warmup": "Calentamiento específico progresivo.",
        "instagram_post": "Texto persuasivo para post con hashtags.",
        "newsletter_text": "Email para socios motivador.",
        "reel_script": "Guion viral para vídeo corto (Hooks visuales)."
    }}
    """
    try:
        response = model.generate_content(prompt)
        clean_text = response.text.strip()
        if clean_text.startswith("```json"):
            clean_text = clean_text.replace("```json", "").replace("```", "").strip()
        elif clean_text.startswith("```"):
            clean_text = clean_text.replace("```", "").strip()
        
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

# --- TAREA ASÍNCRONA IA ---
def async_ai_generation(app, wod_id, user_id):
    """Ejecuta la generación de IA en segundo plano con contexto de aplicación"""
    with app.app_context():
        wod = Wod.query.get(wod_id)
        user = User.query.get(user_id)
        
        if wod and user:
            print(f"🚀 Iniciando generación IA para WOD {wod_id}...")
            if generar_contenido_ai(wod):
                if not user.is_premium:
                    user.credits = max(0, user.credits - 1)
                
                if user.ai_uses_count is None: 
                    user.ai_uses_count = 0
                user.ai_uses_count += 1
                
                db.session.commit()
                print(f"✅ Generación IA completada para WOD {wod_id}")
            else:
                print(f"❌ Fallo en generación IA para WOD {wod_id}")

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
    # --- LÓGICA DE FILTROS ---
    category_filter = request.args.get('category')
    month_filter = request.args.get('month') # Formato esperado YYYY-MM
    
    query = Wod.query.filter_by(user_id=current_user.id)
    
    # Aplicar Filtro Categoría
    if category_filter and category_filter != 'Todas':
        query = query.filter_by(category=category_filter)
        
    # Aplicar Filtro Mes
    if month_filter:
        try:
            year, month = map(int, month_filter.split('-'))
            query = query.filter(extract('year', Wod.date) == year,
                                 extract('month', Wod.date) == month)
        except ValueError:
            pass 

    # Ordenar y ejecutar
    wods = query.order_by(Wod.date.desc()).all()
    
    # --- LOGICA DESPLEGABLE DE MESES INTELIGENTE ---
    meses_es = {
        1: "Enero", 2: "Febrero", 3: "Marzo", 4: "Abril", 5: "Mayo", 6: "Junio",
        7: "Julio", 8: "Agosto", 9: "Septiembre", 10: "Octubre", 11: "Noviembre", 12: "Diciembre"
    }

    available_months_query = db.session.query(
        extract('year', Wod.date).label('year'),
        extract('month', Wod.date).label('month')
    ).filter_by(user_id=current_user.id)\
     .group_by(extract('year', Wod.date), extract('month', Wod.date))\
     .order_by(extract('year', Wod.date).desc(), extract('month', Wod.date).desc())\
     .all()

    month_choices = []
    for m in available_months_query:
        y = int(m.year)
        mo = int(m.month)
        value = f"{y}-{mo:02d}"
        label = f"{meses_es[mo]} {y}"
        month_choices.append((value, label))

    is_super_admin = (current_user.email == ADMIN_EMAIL)
    
    return render_template('index.html', wods=wods, user=current_user, is_super_admin=is_super_admin,
                           current_category=category_filter, current_month=month_filter,
                           month_choices=month_choices)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        gym_name = request.form.get('gym_name')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash('Email ya registrado.', 'error')
            return redirect(url_for('register'))
        
        otp_code = str(random.randint(100000, 999999))
        session['signup_data'] = {'email': email, 'gym_name': gym_name, 'password_hash': generate_password_hash(password), 'otp': otp_code}
        
        body = f"Hola {gym_name},\n\nTu código de verificación es: {otp_code}\n\nIntrodúcelo en la web para activar tu cuenta."
        enviar_email_fondo('Tu Código de Verificación - WOD Master PRO', [email], body)
        return redirect(url_for('verify_code'))
    return render_template('register.html')

@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    if 'signup_data' not in session: return redirect(url_for('register'))
    if request.method == 'POST':
        if request.form.get('code') == session['signup_data']['otp']:
            d = session['signup_data']
            new_user = User(email=d['email'], gym_name=d['gym_name'], password_hash=d['password_hash'], credits=3, is_premium=False)
            db.session.add(new_user)
            db.session.commit()
            session.pop('signup_data', None)
            login_user(new_user)
            enviar_email_fondo('¡Bienvenido a WOD Master PRO! 🚀', [new_user.email], f"Cuenta activada. Tienes 3 créditos gratis.\nEntra aquí: {url_for('index', _external=True)}")
            flash('🎉 ¡Cuenta verificada!', 'success')
            return redirect(url_for('index'))
        else: flash('❌ Código incorrecto.', 'error')
    return render_template('verify_code.html', email=session['signup_data']['email'])

@app.route('/resend_code')
def resend_code():
    if 'signup_data' not in session: return redirect(url_for('register'))
    new_otp = str(random.randint(100000, 999999))
    session['signup_data']['otp'] = new_otp
    enviar_email_fondo('Nuevo Código', [session['signup_data']['email']], f"Tu nuevo código es: {new_otp}")
    flash('Código reenviado.', 'success')
    return redirect(url_for('verify_code'))

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

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        if 'gym_name' in request.form: current_user.gym_name = request.form.get('gym_name'); db.session.commit(); flash('Nombre del gimnasio actualizado.', 'success')
        if 'new_password' in request.form and request.form.get('new_password'): current_user.set_password(request.form.get('new_password')); db.session.commit(); flash('Contraseña actualizada.', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', user=current_user)

@app.route('/privacy')
def privacy(): return render_template('privacy.html', now=datetime.now())
@app.route('/terms')
def terms(): return render_template('terms.html', now=datetime.now())
@app.route('/contact')
def contact(): return render_template('contact.html')

# --- MODIFICADO: AÑADIR WOD (Soporta Clonación) ---
@app.route('/add_wod', methods=['GET', 'POST'])
@login_required
def add_wod():
    cloned_wod = None
    if request.method == 'GET' and 'clone_from' in request.args:
        source_id = request.args.get('clone_from')
        cloned_wod = Wod.query.filter_by(id=source_id, user_id=current_user.id).first()

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
            flash('WOD guardado correctamente.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error: {e}', 'error')

    default_date = datetime.now().strftime('%Y-%m-%d')
    return render_template('add_wod.html', wod=cloned_wod, today_date=default_date)

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
    
    Thread(target=async_ai_generation, args=(app, wod.id, current_user.id)).start()
    
    # CAMBIO: CATEGORÍA SUCCESS (VERDE)
    flash('Contenido Generado.', 'success')
    return redirect(url_for('index'))

@app.route('/export_pdf/<int:wod_id>')
@login_required
def export_pdf(wod_id):
    wod = Wod.query.filter_by(id=wod_id, user_id=current_user.id).first_or_404()
    class PDF(FPDF):
        def header(self):
            self.set_fill_color(41, 121, 255)
            self.rect(0, 0, 210, 40, 'F')
            self.set_font('Arial', 'B', 24)
            self.set_text_color(255, 255, 255)
            self.set_y(10)
            gym_name = wod.user.gym_name.upper().encode('latin-1', 'replace').decode('latin-1')
            self.cell(0, 10, gym_name, 0, 1, 'C')
            self.set_font('Arial', 'I', 12)
            self.cell(0, 10, 'Programacion Profesional', 0, 1, 'C')
            self.ln(20)
        def footer(self):
            self.set_y(-15)
            self.set_font('Arial', 'I', 8)
            self.set_text_color(128)
            self.cell(0, 10, f'Pagina {self.page_no()}/{{nb}} | WOD Master PRO', 0, 0, 'C')
        def chapter_title(self, label):
            self.set_font('Arial', 'B', 12)
            self.set_text_color(41, 121, 255)
            self.set_fill_color(240, 248, 255)
            self.cell(0, 10, f"  {label}", 0, 1, 'L', 1)
            self.ln(4)
        def chapter_body(self, body):
            self.set_font('Arial', '', 11)
            self.set_text_color(0)
            # --- CORRECCIÓN: Limpiar asteriscos de Markdown ---
            # Si el texto es None, usamos string vacío
            text_content = body if body else ""
            clean_body = text_content.replace('**', '').replace('##', '').replace('__', '')
            # --------------------------------------------------
            safe_body = body.encode('latin-1', 'replace').decode('latin-1')
            self.multi_cell(0, 6, safe_body)
            self.ln(5)

    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 20)
    pdf.set_text_color(0)
    safe_title = wod.title.encode('latin-1', 'replace').decode('latin-1')
    pdf.cell(0, 10, safe_title, 0, 1, 'C')
    pdf.set_fill_color(245, 245, 245)
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(80)
    date_str = wod.date.strftime('%d/%m/%Y')
    meta_text = f"FECHA: {date_str}  |  CATEGORIA: {wod.category}  |  TONO: {wod.tone}"
    safe_meta = meta_text.encode('latin-1', 'replace').decode('latin-1')
    pdf.cell(0, 8, safe_meta, 0, 1, 'C', 1)
    pdf.ln(10)
    pdf.chapter_title("ESTRUCTURA DEL ENTRENAMIENTO")
    pdf.chapter_body(wod.structure)
    if wod.objective: pdf.chapter_title("OBJETIVO DEL ESTIMULO"); pdf.chapter_body(wod.objective)
    if wod.ai_warmup: pdf.chapter_title("CALENTAMIENTO (WARM-UP)"); pdf.chapter_body(wod.ai_warmup)
    if wod.ai_strategy: pdf.chapter_title("ESTRATEGIA Y ESCALADOS"); pdf.chapter_body(wod.ai_strategy)
    if wod.notes: pdf.chapter_title("NOTAS ADICIONALES"); pdf.chapter_body(wod.notes)
    buffer = io.BytesIO()
    pdf_output = pdf.output(dest='S').encode('latin-1')
    buffer.write(pdf_output)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"WOD_{wod.date.strftime('%Y%m%d')}.pdf", mimetype='application/pdf')

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_to_delete = current_user
    try:
        Wod.query.filter_by(user_id=user_to_delete.id).delete(synchronize_session=False)
        db.session.delete(user_to_delete)
        db.session.commit()
        logout_user()
        flash('Cuenta eliminada. ¡Adiós!', 'success')
        return redirect(url_for('root'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('settings'))

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
    session = stripe.billing_portal.Session.create(customer=current_user.stripe_customer_id, return_url=url_for('index', _external=True))
    return redirect(session.url)

@app.route('/success')
@login_required
def success(): current_user.is_premium = True; db.session.commit(); return redirect(url_for('index'))

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    event = None
    try: event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except: return 'Error', 400
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        uid = session.get('client_reference_id')
        cust_id = session.get('customer')
        if uid:
            with app.app_context():
                u = User.query.get(uid)
                if u: u.is_premium = True; u.credits = 999999; u.stripe_customer_id = cust_id; db.session.commit()
    elif event['type'] == 'customer.subscription.deleted':
        sub = event['data']['object']
        cust_id = sub.get('customer')
        with app.app_context():
            u = User.query.filter_by(stripe_customer_id=cust_id).first()
            if u: u.is_premium = False; u.credits = 0; db.session.commit()
    return jsonify(success=True)

@app.route('/super_admin')
@login_required
def super_admin():
    if current_user.email != ADMIN_EMAIL: abort(403)
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users, total=len(users), premium=sum(1 for u in users if u.is_premium))

@app.route('/reset_password_request', methods=['GET', 'POST']) 
def reset_request():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user:
            token = s.dumps(user.email, salt='recuperar')
            link = url_for('reset_token', token=token, _external=True)
            enviar_email_fondo('Reset Password', [user.email], f'Link: {link}')
            flash('Correo enviado', 'success')
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try: email = s.loads(token, salt='recuperar', max_age=3600)
    except: return redirect(url_for('reset_request'))
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        user.set_password(request.form.get('password')); db.session.commit()
        return redirect(url_for('login'))
    return render_template('reset_token.html')

@app.errorhandler(404)
def page_not_found(e): return render_template('404.html'), 404
@app.errorhandler(500)
def internal_server_error(e): return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True)