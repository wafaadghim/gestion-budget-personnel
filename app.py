from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta, timedelta
import sqlite3
from nltk.tokenize import word_tokenize
import nltk
import re
import secrets
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
from flask_migrate import Migrate

# Charger les variables d'environnement
load_dotenv()

# Télécharger les données nécessaires pour nltk
nltk.download('punkt')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'votre_cle_secrete'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gestion_budget.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuration OAuth
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID')  # À remplacer par votre ID client Google
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET')  # À remplacer par votre secret client Google
app.config['FACEBOOK_CLIENT_ID'] = os.environ.get('FACEBOOK_CLIENT_ID', 'YOUR_FACEBOOK_APP_ID')  # À remplacer par votre ID app Facebook
app.config['FACEBOOK_CLIENT_SECRET'] = os.environ.get('FACEBOOK_CLIENT_SECRET', 'YOUR_FACEBOOK_APP_SECRET')  # À remplacer par votre secret app Facebook

# Initialisation OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_post'
    }
)

facebook = oauth.register(
    name='facebook',
    client_id=app.config['FACEBOOK_CLIENT_ID'],
    client_secret=app.config['FACEBOOK_CLIENT_SECRET'],
    access_token_url='https://graph.facebook.com/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email public_profile'}
)

# Use the SQLAlchemy `db` and model classes defined in models.py to avoid
# duplicate model declarations and mapping mismatches.
from models import db, User, Expense, Budget, Income, Group, GroupMember, Invitation, Notification

# Initialize the models' SQLAlchemy instance with the Flask app
db.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Fonctions utilitaires pour la gestion des plans premium
def check_premium_access(user, feature=None):
    """
    Vérifie si l'utilisateur a accès à une fonctionnalité premium
    Args:
        user: L'utilisateur à vérifier
        feature: La fonctionnalité spécifique (optionnel)
    Returns:
        bool: True si accès autorisé, False sinon
    """
    return user.is_premium()

def get_user_group_count(user_id):
    """Retourne le nombre de groupes actifs d'un utilisateur"""
    return GroupMember.query.filter_by(
        user_id=user_id,
        is_active=True
    ).count()

def get_monthly_expense_count(user_id, year=None, month=None):
    """Retourne le nombre de dépenses du mois en cours pour un utilisateur"""
    if year is None or month is None:
        today = date.today()
        year = today.year
        month = today.month
    
    return Expense.query.filter(
        Expense.user_id == user_id,
        db.extract('year', Expense.date) == year,
        db.extract('month', Expense.date) == month
    ).count()

def can_create_group(user):
    """Vérifie si l'utilisateur peut créer un nouveau groupe selon son plan"""
    if user.is_premium():
        return True, None  # Pas de limite pour premium
    
    group_count = get_user_group_count(user.id)
    if group_count >= 3:
        return False, "Le plan gratuit limite à 3 groupes maximum. Passez au Premium pour créer plus de groupes."
    
    return True, None

def can_add_expense(user):
    """Vérifie si l'utilisateur peut ajouter une nouvelle dépense selon son plan"""
    if user.is_premium():
        return True, None  # Pas de limite pour premium
    
    expense_count = get_monthly_expense_count(user.id)
    if expense_count >= 100:
        return False, "Le plan gratuit limite à 100 dépenses par mois. Passez au Premium pour ajouter plus de dépenses."
    
    return True, None

# Catégories prédéfinies
CATEGORIES = [
    'Alimentation', 'Transport', 'Logement', 'Loisirs', 
    'Santé', 'Éducation', 'Shopping', 'Autres'
]

# Catégories de revenus
INCOME_CATEGORIES = [
    'Salaire', 'Freelance', 'Investissements', 'Rentes', 
    'Ventes', 'Primes', 'Autres'
]

# Page d'accueil publique
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Page d'accueil (pour utilisateurs connectés - redirige vers dashboard)
@app.route('/index')
@login_required
def index():
    return redirect(url_for('dashboard'))

# Tableau de bord
@app.route('/dashboard')
@login_required
def dashboard():
    # Statistiques du mois en cours
    today = date.today()
    month_expenses = Expense.query.filter(
        Expense.user_id == current_user.id,
        db.extract('month', Expense.date) == today.month,
        db.extract('year', Expense.date) == today.year
    ).all()
    
    total_month = sum(exp.amount for exp in month_expenses)
    
    # Revenus du mois
    month_incomes = Income.query.filter(
        Income.user_id == current_user.id,
        db.extract('month', Income.date) == today.month,
        db.extract('year', Income.date) == today.year
    ).all()
    
    total_month_income = sum(inc.amount for inc in month_incomes)
    balance = total_month_income - total_month
    
    # Dépenses par catégorie
    expenses_by_category = {}
    for exp in month_expenses:
        if exp.category in expenses_by_category:
            expenses_by_category[exp.category] += exp.amount
        else:
            expenses_by_category[exp.category] = exp.amount
    
    # Dernières dépenses
    recent_expenses = Expense.query.filter_by(user_id=current_user.id).order_by(Expense.date.desc()).limit(5).all()
    
    # Invitations en attente
    pending_invitations = Invitation.query.filter_by(
        invited_user_id=current_user.id,
        status='pending'
    ).join(Group).all()
    
    return render_template('dashboard.html', 
                         total_month=total_month,
                         total_month_income=total_month_income,
                         balance=balance,
                         expenses_by_category=expenses_by_category,
                         recent_expenses=recent_expenses,
                         pending_invitations=pending_invitations)

# Inscription
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        first_name = request.form['first_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation des champs
        if not username or not first_name or not email or not password:
            flash('Tous les champs sont obligatoires', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Le mot de passe doit contenir au moins 6 caractères', 'error')
            return redirect(url_for('register'))
        
        # Vérifier si l'utilisateur existe déjà
        if User.query.filter_by(username=username).first():
            flash('Ce nom d\'utilisateur existe déjà', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Cette adresse email est déjà utilisée', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        user = User(
            username=username,
            first_name=first_name,
            email=email,
            password_hash=hashed_password
        )
        
        # Vérifier si l'utilisateur s'inscrit pour un essai gratuit
        trial_param = request.args.get('trial')
        if trial_param == 'premium':
            user.start_trial(30)  # 30 jours d'essai gratuit
        
        db.session.add(user)
        db.session.commit()
        
        flash('Compte créé avec succès! Vous pouvez maintenant vous connecter.', 'success')
        
        # Vérifier s'il y a un token d'invitation en attente
        invitation_token = session.get('invitation_token')
        if invitation_token:
            session.pop('invitation_token', None)
            flash('Vous avez un lien d\'invitation en attente. Consultez vos notifications après connexion.', 'info')
        
        # Vérifier s'il y a un token d'invitation de groupe en attente
        group_invite_token = session.get('group_invite_token')
        if group_invite_token:
            session.pop('group_invite_token', None)
            flash('Vous avez une invitation de groupe en attente. Consultez vos notifications après connexion.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Validation des champs
        if not email or not password:
            flash('Tous les champs sont obligatoires', 'error')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Connexion réussie!', 'success')
            
            # Vérifier s'il y a un token d'invitation en attente
            invitation_token = session.get('invitation_token')
            if invitation_token:
                session.pop('invitation_token', None)
                flash('Vous avez un lien d\'invitation en attente. Consultez vos notifications pour l\'accepter.', 'info')
            
            # Vérifier s'il y a un token d'invitation de groupe en attente
            group_invite_token = session.get('group_invite_token')
            if group_invite_token:
                session.pop('group_invite_token', None)
                flash('Vous avez une invitation de groupe en attente. Consultez vos notifications pour l\'accepter.', 'info')
            
            return redirect(url_for('dashboard'))
        else:
            flash('Adresse email ou mot de passe incorrect', 'error')
    
    return render_template('login.html')

# Mot de passe oublié
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        if not email:
            flash('Veuillez saisir votre adresse email', 'error')
            return redirect(url_for('forgot_password'))
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Générer un token de réinitialisation
            reset_token = secrets.token_urlsafe(32)
            
            # Ici, en production, vous enverriez un email avec le lien de réinitialisation
            # Pour l'instant, on affiche le lien dans un message flash pour la démonstration
            reset_url = url_for('reset_password', token=reset_token, _external=True)
            
            # Stocker le token temporairement (en production, utiliser Redis ou une table dédiée)
            if not hasattr(app, 'reset_tokens'):
                app.reset_tokens = {}
            app.reset_tokens[reset_token] = {
                'user_id': user.id,
                'email': email,
                'expires': datetime.utcnow() + timedelta(hours=1)  # Expire dans 1 heure
            }
            
            flash(f'Lien de réinitialisation envoyé ! Pour la démonstration, voici le lien : {reset_url}', 'success')
        else:
            # Même message pour éviter l'énumération d'emails
            flash('Si cette adresse email existe dans notre système, vous recevrez un lien de réinitialisation.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

# Réinitialiser le mot de passe
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Vérifier si le token est valide
    if not hasattr(app, 'reset_tokens') or token not in app.reset_tokens:
        flash('Lien de réinitialisation invalide ou expiré', 'error')
        return redirect(url_for('login'))
    
    token_data = app.reset_tokens[token]
    
    # Vérifier si le token n'a pas expiré
    if datetime.utcnow() > token_data['expires']:
        del app.reset_tokens[token]
        flash('Lien de réinitialisation expiré', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas', 'error')
            return redirect(request.url)
        
        if len(password) < 6:
            flash('Le mot de passe doit contenir au moins 6 caractères', 'error')
            return redirect(request.url)
        
        # Mettre à jour le mot de passe
        user = User.query.get(token_data['user_id'])
        if user:
            user.password_hash = generate_password_hash(password)
            db.session.commit()
            
            # Supprimer le token utilisé
            del app.reset_tokens[token]
            
            flash('Mot de passe réinitialisé avec succès ! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Utilisateur non trouvé', 'error')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html')

# Déconnexion
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Vous avez été déconnecté', 'success')
    return redirect(url_for('login'))

# Connexion avec Google
@app.route('/login/google')
def login_google():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

# Callback Google
@app.route('/login/google/authorize')
def google_authorize():
    try:
        token = google.authorize_access_token()
        resp = google.get('https://www.googleapis.com/oauth2/v2/userinfo')
        user_info = resp.json()

        # Vérifier si l'utilisateur existe déjà
        user = User.query.filter_by(oauth_id=user_info['id'], oauth_provider='google').first()

        if not user:
            # Créer un nouvel utilisateur
            username = user_info.get('email', f"google_{user_info['id']}")
            # S'assurer que le username est unique
            base_username = username.split('@')[0] if '@' in username else username
            counter = 1
            final_username = base_username
            while User.query.filter_by(username=final_username).first():
                final_username = f"{base_username}_{counter}"
                counter += 1

            user = User(
                username=final_username,
                email=user_info.get('email'),
                oauth_provider='google',
                oauth_id=user_info['id']
            )
            db.session.add(user)
            db.session.commit()

        login_user(user)
        flash('Connexion avec Google réussie!', 'success')
        
        # Vérifier s'il y a un token d'invitation de groupe en attente
        group_invite_token = session.get('group_invite_token')
        if group_invite_token:
            session.pop('group_invite_token', None)
            flash('Vous avez une invitation de groupe en attente. Consultez vos notifications pour l\'accepter.', 'info')
        
        return redirect(url_for('dashboard'))

    except Exception as e:
        flash('Erreur lors de la connexion avec Google', 'error')
        return redirect(url_for('login'))

# Connexion avec Facebook
@app.route('/login/facebook')
def login_facebook():
    redirect_uri = url_for('facebook_authorize', _external=True)
    return facebook.authorize_redirect(redirect_uri)

# Callback Facebook
@app.route('/login/facebook/authorize')
def facebook_authorize():
    try:
        token = facebook.authorize_access_token()
        resp = facebook.get('/me?fields=id,name,email')
        user_info = resp.json()

        # Vérifier si l'utilisateur existe déjà
        user = User.query.filter_by(oauth_id=user_info['id'], oauth_provider='facebook').first()

        if not user:
            # Créer un nouvel utilisateur
            username = user_info.get('email', f"facebook_{user_info['id']}")
            # S'assurer que le username est unique
            base_username = username.split('@')[0] if '@' in username else username
            counter = 1
            final_username = base_username
            while User.query.filter_by(username=final_username).first():
                final_username = f"{base_username}_{counter}"
                counter += 1

            user = User(
                username=final_username,
                email=user_info.get('email'),
                oauth_provider='facebook',
                oauth_id=user_info['id']
            )
            db.session.add(user)
            db.session.commit()

        login_user(user)
        flash('Connexion avec Facebook réussie!', 'success')
        
        # Vérifier s'il y a un token d'invitation de groupe en attente
        group_invite_token = session.get('group_invite_token')
        if group_invite_token:
            session.pop('group_invite_token', None)
            flash('Vous avez une invitation de groupe en attente. Consultez vos notifications pour l\'accepter.', 'info')
        
        return redirect(url_for('dashboard'))

    except Exception as e:
        flash('Erreur lors de la connexion avec Facebook', 'error')
        return redirect(url_for('login'))

# Ajouter une dépense
@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    # Vérifier les limitations du plan gratuit
    can_add, message = can_add_expense(current_user)
    if not can_add:
        flash(message, 'warning')
        return redirect(url_for('expenses'))
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        category = request.form['category']
        description = request.form['description']
        expense_date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        
        expense = Expense(
            amount=amount,
            category=category,
            description=description,
            date=expense_date,
            user_id=current_user.id
        )
        
        db.session.add(expense)
        db.session.commit()
        
        flash('Dépense ajoutée avec succès!', 'success')
        return redirect(url_for('expenses'))
    
    return render_template('add_expense.html', categories=CATEGORIES)

# Liste des dépenses
@app.route('/expenses')
@login_required
def expenses():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Filtrage par catégorie si spécifié
    category_filter = request.args.get('category')
    query = Expense.query.filter_by(user_id=current_user.id)
    
    if category_filter:
        query = query.filter_by(category=category_filter)
    
    expenses = query.order_by(Expense.date.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('expenses.html', expenses=expenses, selected_category=category_filter)

# Modifier une dépense
@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    
    if expense.user_id != current_user.id:
        flash('Accès non autorisé', 'error')
        return redirect(url_for('expenses'))
    
    if request.method == 'POST':
        expense.amount = float(request.form['amount'])
        expense.category = request.form['category']
        expense.description = request.form['description']
        expense.date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        
        db.session.commit()
        flash('Dépense modifiée avec succès!', 'success')
        return redirect(url_for('expenses'))
    
    return render_template('edit_expense.html', expense=expense, categories=CATEGORIES)

# Supprimer une dépense
@app.route('/delete_expense/<int:expense_id>')
@login_required
def delete_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    
    if expense.user_id != current_user.id:
        flash('Accès non autorisé', 'error')
        return redirect(url_for('expenses'))
    
    db.session.delete(expense)
    db.session.commit()
    flash('Dépense supprimée avec succès!', 'success')
    return redirect(url_for('expenses'))

# Modifier une dépense de groupe
@app.route('/group/<int:group_id>/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_group_expense(group_id, expense_id):
    group = Group.query.get_or_404(group_id)
    expense = Expense.query.get_or_404(expense_id)
    
    # Vérifier que la dépense appartient au groupe et à l'utilisateur
    if expense.group_id != group_id or expense.user_id != current_user.id:
        flash('Accès non autorisé', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    
    # Vérifier que l'utilisateur est membre du groupe
    is_member = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id,
        is_active=True
    ).first()
    
    if not is_member:
        flash('Vous devez être membre du groupe pour modifier des dépenses', 'error')
        return redirect(url_for('groups'))
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        category = request.form['category']
        description = request.form['description']
        expense_date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        
        # Gestion du fichier justificatif
        justificatif_filename = expense.justificatif  # Garder l'ancien par défaut
        if 'justificatif' in request.files:
            file = request.files['justificatif']
            if file and file.filename != '':
                # Vérifier l'extension du fichier
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
                if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                    # Supprimer l'ancien fichier s'il existe
                    if expense.justificatif:
                        old_file_path = os.path.join(app.root_path, 'static', 'uploads', 'justificatifs', expense.justificatif)
                        if os.path.exists(old_file_path):
                            os.remove(old_file_path)
                    
                    # Générer un nom de fichier unique
                    import uuid
                    filename = str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower()
                    file_path = os.path.join(app.root_path, 'static', 'uploads', 'justificatifs', filename)
                    
                    # Créer le dossier s'il n'existe pas
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    
                    # Sauvegarder le fichier
                    file.save(file_path)
                    justificatif_filename = filename
                else:
                    flash('Type de fichier non autorisé. Seules les images (PNG, JPG, JPEG, GIF) et les PDF sont acceptés.', 'error')
                    return redirect(request.url)
        
        expense.amount = amount
        expense.category = category
        expense.description = description
        expense.date = expense_date
        expense.justificatif = justificatif_filename
        
        db.session.commit()
        flash('Dépense modifiée avec succès!', 'success')
        return redirect(url_for('group_detail', group_id=group_id))
    
    return render_template('edit_group_expense.html', group=group, expense=expense, categories=CATEGORIES, today=date.today())

# Supprimer une dépense de groupe
@app.route('/group/<int:group_id>/delete_expense/<int:expense_id>')
@login_required
def delete_group_expense(group_id, expense_id):
    group = Group.query.get_or_404(group_id)
    expense = Expense.query.get_or_404(expense_id)
    
    # Vérifier que la dépense appartient au groupe et à l'utilisateur
    if expense.group_id != group_id or expense.user_id != current_user.id:
        flash('Accès non autorisé', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    
    # Supprimer le fichier justificatif s'il existe
    if expense.justificatif:
        file_path = os.path.join(app.root_path, 'static', 'uploads', 'justificatifs', expense.justificatif)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    db.session.delete(expense)
    db.session.commit()
    flash('Dépense supprimée avec succès!', 'success')
    return redirect(url_for('group_detail', group_id=group_id))

# Gestion des budgets
@app.route('/budgets')
@login_required
def budgets():
    today = date.today()
    budgets = Budget.query.filter_by(
        user_id=current_user.id,
        month=today.month,
        year=today.year
    ).all()
    
    # Calcul des dépenses par catégorie pour le mois en cours
    expenses = Expense.query.filter(
        Expense.user_id == current_user.id,
        db.extract('month', Expense.date) == today.month,
        db.extract('year', Expense.date) == today.year
    ).all()
    
    expenses_by_category = {}
    for exp in expenses:
        if exp.category in expenses_by_category:
            expenses_by_category[exp.category] += exp.amount
        else:
            expenses_by_category[exp.category] = exp.amount
    
    return render_template('budgets.html', 
                         budgets=budgets, 
                         expenses_by_category=expenses_by_category,
                         categories=CATEGORIES)

# Ajouter/modifier un budget
@app.route('/add_budget', methods=['POST'])
@login_required
def add_budget():
    category = request.form['category']
    amount = float(request.form['amount'])
    today = date.today()
    
    # Vérifier si un budget existe déjà pour cette catégorie ce mois-ci
    existing_budget = Budget.query.filter_by(
        user_id=current_user.id,
        category=category,
        month=today.month,
        year=today.year
    ).first()
    
    if existing_budget:
        existing_budget.amount = amount
        flash('Budget modifié avec succès!', 'success')
    else:
        budget = Budget(
            category=category,
            amount=amount,
            month=today.month,
            year=today.year,
            user_id=current_user.id
        )
        db.session.add(budget)
        flash('Budget ajouté avec succès!', 'success')
    
    db.session.commit()
    return redirect(url_for('budgets'))

# Gestion des revenus
@app.route('/incomes')
@login_required
def incomes():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    incomes = Income.query.filter_by(user_id=current_user.id).order_by(Income.date.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Calcul du total des revenus du mois en cours
    today = date.today()
    month_incomes = Income.query.filter(
        Income.user_id == current_user.id,
        db.extract('month', Income.date) == today.month,
        db.extract('year', Income.date) == today.year
    ).all()
    total_month_income = sum(inc.amount for inc in month_incomes)
    
    return render_template('incomes.html', incomes=incomes, total_month_income=total_month_income, income_categories=INCOME_CATEGORIES)

# Ajouter un revenu
@app.route('/add_income', methods=['GET', 'POST'])
@login_required
def add_income():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        category = request.form['category']
        description = request.form['description']
        income_date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        
        income = Income(
            amount=amount,
            category=category,
            description=description,
            date=income_date,
            user_id=current_user.id
        )
        
        db.session.add(income)
        db.session.commit()
        
        flash('Revenu ajouté avec succès!', 'success')
        return redirect(url_for('incomes'))
    
    return render_template('add_income.html', income_categories=INCOME_CATEGORIES, today=date.today())

# Modifier un revenu
@app.route('/edit_income/<int:income_id>', methods=['GET', 'POST'])
@login_required
def edit_income(income_id):
    income = Income.query.get_or_404(income_id)
    
    if income.user_id != current_user.id:
        flash('Accès non autorisé', 'error')
        return redirect(url_for('incomes'))
    
    if request.method == 'POST':
        income.amount = float(request.form['amount'])
        income.category = request.form['category']
        income.description = request.form['description']
        income.date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        
        db.session.commit()
        flash('Revenu modifié avec succès!', 'success')
        return redirect(url_for('incomes'))
    
    return render_template('edit_income.html', income=income, income_categories=INCOME_CATEGORIES)

# Supprimer un revenu
@app.route('/delete_income/<int:income_id>')
@login_required
def delete_income(income_id):
    income = Income.query.get_or_404(income_id)
    
    if income.user_id != current_user.id:
        flash('Accès non autorisé', 'error')
        return redirect(url_for('incomes'))
    
    db.session.delete(income)
    db.session.commit()
    flash('Revenu supprimé avec succès!', 'success')
    return redirect(url_for('incomes'))

# Rapports et statistiques
@app.route('/reports')
@login_required
def reports():
    # Statistiques par mois
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    
    monthly_data = {}
    for exp in expenses:
        month_year = f"{exp.date.month}/{exp.date.year}"
        if month_year in monthly_data:
            monthly_data[month_year] += exp.amount
        else:
            monthly_data[month_year] = exp.amount
    
    # Dépenses par catégorie (toutes périodes)
    category_data = {}
    for exp in expenses:
        if exp.category in category_data:
            category_data[exp.category] += exp.amount
        else:
            category_data[exp.category] = exp.amount
    
    return render_template('reports.html', 
                         monthly_data=monthly_data,
                         category_data=category_data)

# API pour les données du tableau de bord (JSON)
@app.route('/api/expenses_data')
@login_required
def api_expenses_data():
    today = date.today()
    expenses = Expense.query.filter(
        Expense.user_id == current_user.id,
        db.extract('month', Expense.date) == today.month,
        db.extract('year', Expense.date) == today.year
    ).all()
    
    data = {}
    for exp in expenses:
        if exp.category in data:
            data[exp.category] += exp.amount
        else:
            data[exp.category] = exp.amount
    
    return jsonify(data)

# Saisie vocale/intelligente (optionnelle)
@app.route('/smart_add', methods=['POST'])
@login_required
def smart_add():
    text = request.form['text']
    
    # Tokenization simple avec nltk
    tokens = word_tokenize(text.lower())
    
    # Recherche de montants
    amount = None
    for token in tokens:
        if re.match(r'^\d+([.,]\d+)?$', token):
            amount = float(token.replace(',', '.'))
            break
    
    # Recherche de catégories
    category = 'Autres'
    for cat in CATEGORIES:
        if cat.lower() in text.lower():
            category = cat
            break
    
    return jsonify({
        'amount': amount,
        'category': category,
        'description': text
    })

# Page Balance et Statistiques
@app.route('/balance')
@login_required
def balance():
    today = date.today()
    
    # Revenus du mois
    month_incomes = Income.query.filter(
        Income.user_id == current_user.id,
        db.extract('month', Income.date) == today.month,
        db.extract('year', Income.date) == today.year
    ).all()
    total_income = sum(inc.amount for inc in month_incomes)
    
    # Dépenses du mois
    month_expenses = Expense.query.filter(
        Expense.user_id == current_user.id,
        db.extract('month', Expense.date) == today.month,
        db.extract('year', Expense.date) == today.year
    ).all()
    total_expenses = sum(exp.amount for exp in month_expenses)
    
    # Balance
    balance = total_income - total_expenses
    
    # Statistiques annuelles
    year_incomes = Income.query.filter(
        Income.user_id == current_user.id,
        db.extract('year', Income.date) == today.year
    ).all()
    total_year_income = sum(inc.amount for inc in year_incomes)
    
    year_expenses = Expense.query.filter(
        Expense.user_id == current_user.id,
        db.extract('year', Expense.date) == today.year
    ).all()
    total_year_expenses = sum(exp.amount for exp in year_expenses)
    
    year_balance = total_year_income - total_year_expenses
    
    # Évolution mensuelle (derniers 6 mois)
    monthly_data = []
    for i in range(5, -1, -1):
        month = today.month - i
        year = today.year
        if month <= 0:
            month += 12
            year -= 1
        
        month_inc = sum(inc.amount for inc in Income.query.filter(
            Income.user_id == current_user.id,
            db.extract('month', Income.date) == month,
            db.extract('year', Income.date) == year
        ).all())
        
        month_exp = sum(exp.amount for exp in Expense.query.filter(
            Expense.user_id == current_user.id,
            db.extract('month', Expense.date) == month,
            db.extract('year', Expense.date) == year
        ).all())
        
        monthly_data.append({
            'month': f"{month:02d}/{year}",
            'income': month_inc,
            'expenses': month_exp,
            'balance': month_inc - month_exp
        })
    
    return render_template('balance.html', 
                         total_income=total_income,
                         total_expenses=total_expenses,
                         balance=balance,
                         total_year_income=total_year_income,
                         total_year_expenses=total_year_expenses,
                         year_balance=year_balance,
                         monthly_data=monthly_data)

# Gestion des groupes
@app.route('/groups')
@login_required
def groups():
    # Groupes créés par l'utilisateur
    created_groups = Group.query.filter_by(created_by=current_user.id).all()

    # Groupes où l'utilisateur est membre
    member_groups = Group.query.join(GroupMember).filter(
        GroupMember.user_id == current_user.id,
        GroupMember.is_active == True
    ).all()

    # Invitations en attente
    pending_invitations = Invitation.query.filter_by(
        invited_user_id=current_user.id,
        status='pending'
    ).join(Group).all()

    return render_template('groups.html',
                         created_groups=created_groups,
                         member_groups=member_groups,
                         pending_invitations=pending_invitations)

# Créer un groupe
@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    # Vérifier les limitations du plan gratuit
    can_create, message = can_create_group(current_user)
    if not can_create:
        flash(message, 'warning')
        return redirect(url_for('groups'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        location = request.form.get('location', '')
        date_sortie = request.form.get('date_sortie')
        heure_sortie = request.form.get('heure_sortie')
        nombre_jours = request.form.get('nombre_jours', 1, type=int)

        group = Group(
            name=name,
            description=description,
            location=location,
            date_sortie=datetime.strptime(date_sortie, '%d/%m/%Y').date() if date_sortie else None,
            heure_sortie=datetime.strptime(heure_sortie, '%H:%M').time() if heure_sortie else None,
            nombre_jours=nombre_jours,
            created_by=current_user.id,
            invite_token=secrets.token_urlsafe(32)  # Générer un token permanent unique
        )

        db.session.add(group)
        db.session.commit()

        # Ajouter le créateur comme membre admin
        member = GroupMember(
            group_id=group.id,
            user_id=current_user.id,
            is_admin=True
        )
        db.session.add(member)
        db.session.commit()

        flash('Groupe créé avec succès!', 'success')
        return redirect(url_for('groups'))

    return render_template('create_group.html')

# Détails d'un groupe
@app.route('/group/<int:group_id>')
@login_required
def group_detail(group_id):
    group = Group.query.get_or_404(group_id)

    # Vérifier si l'utilisateur est membre ou créateur
    is_member = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id,
        is_active=True
    ).first()

    is_creator = group.created_by == current_user.id

    if not (is_member or is_creator):
        flash('Accès non autorisé à ce groupe', 'error')
        return redirect(url_for('groups'))

    # Membres du groupe
    members = GroupMember.query.filter_by(group_id=group_id, is_active=True).join(User).all()

    # Dépenses du groupe
    group_expenses = Expense.query.filter_by(group_id=group_id).order_by(Expense.date.desc()).all()

    # Statistiques du groupe
    total_expenses = sum(exp.amount for exp in group_expenses)
    member_count = len(members)

    return render_template('group_detail.html',
                         group=group,
                         members=members,
                         expenses=group_expenses,
                         total_expenses=total_expenses,
                         member_count=member_count,
                         is_creator=is_creator,
                         is_admin=is_member.is_admin if is_member else False)

# Modifier un groupe
@app.route('/group/<int:group_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_group(group_id):
    group = Group.query.get_or_404(group_id)

    # Vérifier si l'utilisateur est le créateur du groupe
    if group.created_by != current_user.id:
        flash('Seul le créateur du groupe peut le modifier', 'error')
        return redirect(url_for('group_detail', group_id=group_id))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        location = request.form.get('location', '')
        date_sortie = request.form.get('date_sortie')
        heure_sortie = request.form.get('heure_sortie')
        nombre_jours = request.form.get('nombre_jours', 1, type=int)

        # Mettre à jour le groupe
        group.name = name
        group.description = description
        group.location = location
        group.date_sortie = datetime.strptime(date_sortie, '%d/%m/%Y').date() if date_sortie else None
        group.heure_sortie = datetime.strptime(heure_sortie, '%H:%M').time() if heure_sortie else None
        group.nombre_jours = nombre_jours

        db.session.commit()

        flash('Groupe modifié avec succès!', 'success')
        return redirect(url_for('group_detail', group_id=group_id))

    return render_template('edit_group.html', group=group)

# Supprimer un groupe
@app.route('/group/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_group(group_id):
    group = Group.query.get_or_404(group_id)

    # Vérifier si l'utilisateur est le créateur du groupe
    if group.created_by != current_user.id:
        flash('Seul le créateur du groupe peut le supprimer', 'error')
        return redirect(url_for('group_detail', group_id=group_id))

    # Vérifier s'il y a des dépenses dans le groupe
    expense_count = Expense.query.filter_by(group_id=group_id).count()
    if expense_count > 0:
        flash(f'Impossible de supprimer le groupe car il contient {expense_count} dépense(s). Supprimez d\'abord toutes les dépenses.', 'error')
        return redirect(url_for('group_detail', group_id=group_id))

    group_name = group.name

    # Supprimer toutes les invitations liées au groupe
    Invitation.query.filter_by(group_id=group_id).delete()

    # Supprimer tous les membres du groupe
    GroupMember.query.filter_by(group_id=group_id).delete()

    # Supprimer le groupe
    db.session.delete(group)
    db.session.commit()

    flash(f'Groupe "{group_name}" supprimé avec succès!', 'success')
    return redirect(url_for('groups'))

# Inviter un membre
@app.route('/group/<int:group_id>/invite', methods=['POST'])
@login_required
def invite_member(group_id):
    group = Group.query.get_or_404(group_id)

    # Vérifier si le groupe est expiré
    if group.is_expired():
        flash('Ce groupe est expiré. Vous ne pouvez plus envoyer d\'invitations.', 'warning')
        return redirect(url_for('group_detail', group_id=group_id))

    # Vérifier si l'utilisateur est admin du groupe
    is_admin = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id,
        is_admin=True
    ).first()

    if not is_admin and group.created_by != current_user.id:
        flash('Seuls les administrateurs peuvent inviter des membres', 'error')
        return redirect(url_for('group_detail', group_id=group_id))

    invitation_type = request.form.get('invitation_type', 'username')

    if invitation_type == 'username':
        username = request.form['username']

        # Trouver l'utilisateur
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('Utilisateur non trouvé', 'error')
            return redirect(url_for('group_detail', group_id=group_id))

        # Vérifier si déjà membre
        existing_member = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=user.id
        ).first()

        if existing_member:
            flash('Cet utilisateur est déjà membre du groupe', 'error')
            return redirect(url_for('group_detail', group_id=group_id))

        # Vérifier si invitation existe déjà
        existing_invitation = Invitation.query.filter_by(
            group_id=group_id,
            invited_user_id=user.id
        ).first()

        if existing_invitation:
            flash('Une invitation est déjà en attente pour cet utilisateur', 'error')
            return redirect(url_for('group_detail', group_id=group_id))

        # Créer l'invitation
        invitation = Invitation(
            group_id=group_id,
            sender_id=current_user.id,
            invited_user_id=user.id,
            token=secrets.token_urlsafe(32)
        )

        db.session.add(invitation)

        # Créer une notification pour l'utilisateur invité
        notification = Notification(
            user_id=user.id,
            type='group_invitation',
            title='Nouvelle invitation de groupe',
            message=f'{current_user.username} vous a invité à rejoindre le groupe "{group.name}"',
            group_id=group_id,
            related_user_id=current_user.id
        )
        db.session.add(notification)

        db.session.commit()

        flash(f'Invitation envoyée à {username}', 'success')

    elif invitation_type == 'link':
        # Créer une invitation par lien
        invitation = Invitation(
            group_id=group_id,
            sender_id=current_user.id,
            token=secrets.token_urlsafe(32)
        )

        db.session.add(invitation)
        db.session.commit()

        # Rediriger vers la page de partage du lien
        return redirect(url_for('invite_link', token=invitation.token))

    return redirect(url_for('group_detail', group_id=group_id))

# Générer un token d'invitation pour les liens
@app.route('/group/<int:group_id>/generate_token', methods=['POST'])
@login_required
def generate_invite_token(group_id):
    group = Group.query.get_or_404(group_id)

    # Vérifier si le groupe est expiré
    if group.is_expired():
        return jsonify({'success': False, 'message': 'Ce groupe est expiré. Vous ne pouvez plus envoyer d\'invitations.'})

    # Vérifier si l'utilisateur est admin du groupe
    is_admin = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id,
        is_admin=True
    ).first()

    if not is_admin and group.created_by != current_user.id:
        return jsonify({'success': False, 'message': 'Accès non autorisé'})

    # Créer une nouvelle invitation avec token
    invitation = Invitation(
        group_id=group_id,
        sender_id=current_user.id,
        token=secrets.token_urlsafe(32)
    )

    db.session.add(invitation)
    db.session.commit()

    invite_url = url_for('accept_invitation', token=invitation.token, _external=True)

    return jsonify({
        'success': True,
        'invite_url': invite_url,
        'token': invitation.token
    })

# Page de partage du lien d'invitation
@app.route('/invite_link/<token>')
@login_required
def invite_link(token):
    invitation = Invitation.query.filter_by(token=token).first()

    if not invitation:
        flash('Lien d\'invitation invalide', 'error')
        return redirect(url_for('dashboard'))

    # Vérifier si l'utilisateur est autorisé (créateur ou admin du groupe)
    group = Group.query.get(invitation.group_id)
    is_admin = GroupMember.query.filter_by(
        group_id=invitation.group_id,
        user_id=current_user.id,
        is_admin=True
    ).first()

    if not (is_admin or group.created_by == current_user.id):
        flash('Accès non autorisé', 'error')
        return redirect(url_for('dashboard'))

    invitation_url = url_for('accept_invitation', token=token, _external=True)

    # Encoder pour les liens de partage
    from urllib.parse import quote
    whatsapp_text = f"Rejoins mon groupe {group.name} sur Cagnotte ! {invitation_url}"
    whatsapp_url = f"https://wa.me/?text={quote(whatsapp_text)}"
    messenger_url = f"https://www.facebook.com/dialog/send?link={quote(invitation_url)}&app_id=123456789&redirect_uri={quote(url_for('invite_link', token=token, _external=True))}"

    return render_template('invite_link.html',
                         invitation_url=invitation_url,
                         group=group,
                         token=token,
                         whatsapp_url=whatsapp_url,
                         messenger_url=messenger_url)

# Accepter une invitation par lien
@app.route('/invite/<token>')
def accept_invitation(token):
    invitation = Invitation.query.filter_by(token=token).first()

    if not invitation:
        flash('Lien d\'invitation invalide ou expiré', 'error')
        return redirect(url_for('login'))

    # Vérifier si l'invitation a expiré
    if invitation.expires_at < datetime.utcnow():
        invitation.status = 'expired'
        db.session.commit()
        flash('Cette invitation a expiré', 'error')
        return redirect(url_for('login'))

    # Vérifier si l'invitation a déjà été utilisée
    if invitation.status != 'pending':
        if invitation.status == 'accepted':
            flash('Cette invitation a déjà été acceptée', 'info')
        elif invitation.status == 'rejected':
            flash('Cette invitation a été refusée', 'warning')
        else:
            flash('Cette invitation n\'est plus valide', 'error')
        return redirect(url_for('login'))

    group = Group.query.get(invitation.group_id)

    # Si l'utilisateur n'est pas connecté, sauvegarder le token et rediriger vers login
    if not current_user.is_authenticated:
        session['invitation_token'] = token
        flash('Veuillez vous connecter pour accepter cette invitation', 'info')
        return redirect(url_for('login'))

    # Toujours afficher la page d'acceptation/refus pour les utilisateurs connectés
    return render_template('accept_invitation.html', group=group, token=token)

# Accepter une invitation par token permanent de groupe
@app.route('/join/<token>')
def join_group_by_token(token):
    group = Group.query.filter_by(invite_token=token).first()

    if not group:
        flash('Lien d\'invitation invalide', 'error')
        return redirect(url_for('login'))

    # Vérifier si le groupe est expiré
    if group.is_expired():
        flash('Ce groupe est expiré et n\'accepte plus de nouveaux membres', 'warning')
        return redirect(url_for('login'))

    # Si l'utilisateur n'est pas connecté, sauvegarder le token et rediriger vers login
    if not current_user.is_authenticated:
        session['group_invite_token'] = token
        flash('Veuillez vous connecter pour rejoindre ce groupe', 'info')
        return redirect(url_for('login'))

    # Vérifier si déjà membre
    existing_member = GroupMember.query.filter_by(
        group_id=group.id,
        user_id=current_user.id
    ).first()

    if existing_member:
        if existing_member.is_active:
            flash('Vous êtes déjà membre de ce groupe', 'info')
        else:
            # Réactiver le membre
            existing_member.is_active = True
            db.session.commit()
            flash(f'Bienvenue de retour dans le groupe "{group.name}" !', 'success')
        return redirect(url_for('group_detail', group_id=group.id))

    # Toujours afficher la page d'acceptation/refus pour les utilisateurs connectés
    return render_template('join_group.html', group=group, token=token)

# Accepter l'invitation à un groupe par token permanent
@app.route('/join_group/<token>')
@login_required
def accept_group_invitation_by_token(token):
    group = Group.query.filter_by(invite_token=token).first()

    if not group:
        flash('Invitation invalide', 'error')
        return redirect(url_for('dashboard'))

    # Vérifier si le groupe est expiré
    if group.is_expired():
        flash('Ce groupe est expiré et n\'accepte plus de nouveaux membres', 'warning')
        return redirect(url_for('dashboard'))

    # Vérifier si déjà membre
    existing_member = GroupMember.query.filter_by(
        group_id=group.id,
        user_id=current_user.id
    ).first()

    if existing_member:
        if existing_member.is_active:
            flash('Vous êtes déjà membre de ce groupe', 'info')
        else:
            # Réactiver le membre
            existing_member.is_active = True
            db.session.commit()
            flash(f'Bienvenue de retour dans le groupe "{group.name}" !', 'success')
        return redirect(url_for('group_detail', group_id=group.id))

    # Ajouter comme membre
    member = GroupMember(
        group_id=group.id,
        user_id=current_user.id
    )
    db.session.add(member)

    # Créer une notification pour tous les membres du groupe (sauf le nouveau membre)
    group_members = GroupMember.query.filter_by(
        group_id=group.id,
        is_active=True
    ).filter(GroupMember.user_id != current_user.id).all()

    for group_member in group_members:
        notification = Notification(
            user_id=group_member.user_id,
            type='group_join',
            title='Nouveau membre dans le groupe',
            message=f'{current_user.username} a rejoint le groupe "{group.name}"',
            group_id=group.id,
            related_user_id=current_user.id
        )
        db.session.add(notification)

    db.session.commit()

    flash(f'Bienvenue dans le groupe "{group.name}" !', 'success')
    return redirect(url_for('group_detail', group_id=group.id))

# Refuser l'invitation à un groupe par token permanent
@app.route('/decline_group/<token>')
@login_required
def decline_group_invitation_by_token(token):
    group = Group.query.filter_by(invite_token=token).first()

    if not group:
        flash('Invitation invalide', 'error')
        return redirect(url_for('dashboard'))

    flash(f'Invitation pour le groupe "{group.name}" refusée', 'info')
    return redirect(url_for('dashboard'))
    invitation = Invitation.query.filter_by(token=token).first()

    if not invitation or invitation.status != 'pending':
        flash('Invitation invalide', 'error')
        return redirect(url_for('dashboard'))

    # Vérifier si déjà membre
    existing_member = GroupMember.query.filter_by(
        group_id=invitation.group_id,
        user_id=current_user.id
    ).first()

    if existing_member:
        flash('Vous êtes déjà membre de ce groupe', 'info')
        return redirect(url_for('group_detail', group_id=invitation.group_id))

    # Ajouter comme membre
    member = GroupMember(
        group_id=invitation.group_id,
        user_id=current_user.id
    )
    db.session.add(member)
    invitation.status = 'accepted'
    invitation.invited_user_id = current_user.id

    # Créer une notification pour tous les membres du groupe (sauf le nouveau membre)
    group_members = GroupMember.query.filter_by(
        group_id=invitation.group_id,
        is_active=True
    ).filter(GroupMember.user_id != current_user.id).all()

    group = Group.query.get(invitation.group_id)
    for group_member in group_members:
        notification = Notification(
            user_id=group_member.user_id,
            type='group_join',
            title='Nouveau membre dans le groupe',
            message=f'{current_user.username} a rejoint le groupe "{group.name}"',
            group_id=invitation.group_id,
            related_user_id=current_user.id
        )
        db.session.add(notification)

    db.session.commit()

    flash(f'Bienvenue dans le groupe "{group.name}" !', 'success')
    return redirect(url_for('group_detail', group_id=invitation.group_id))

# Refuser une invitation par token
@app.route('/reject_invitation/<token>')
@login_required
def reject_invitation_by_token(token):
    invitation = Invitation.query.filter_by(token=token).first()

    if not invitation or invitation.status != 'pending':
        flash('Invitation invalide', 'error')
        return redirect(url_for('dashboard'))

    invitation.status = 'rejected'
    db.session.commit()

    group = Group.query.get(invitation.group_id)
    flash(f'Invitation pour le groupe "{group.name}" refusée', 'info')
    return redirect(url_for('dashboard'))

# Accepter une invitation depuis la page des groupes
@app.route('/accept_invitation/<int:invitation_id>')
@login_required
def accept_invitation_from_groups(invitation_id):
    invitation = Invitation.query.get_or_404(invitation_id)

    # Vérifier que l'invitation appartient à l'utilisateur actuel
    if invitation.invited_user_id != current_user.id:
        flash('Accès non autorisé', 'error')
        return redirect(url_for('groups'))

    if invitation.status != 'pending':
        flash('Cette invitation n\'est plus valide', 'error')
        return redirect(url_for('groups'))

    # Vérifier si déjà membre
    existing_member = GroupMember.query.filter_by(
        group_id=invitation.group_id,
        user_id=current_user.id
    ).first()

    if existing_member:
        flash('Vous êtes déjà membre de ce groupe', 'info')
        return redirect(url_for('group_detail', group_id=invitation.group_id))

    # Ajouter comme membre
    member = GroupMember(
        group_id=invitation.group_id,
        user_id=current_user.id
    )
    db.session.add(member)
    invitation.status = 'accepted'
    db.session.commit()

    # Récupérer le groupe pour les notifications
    group = Group.query.get(invitation.group_id)

    # Créer une notification pour tous les membres du groupe (sauf le nouveau membre)
    group_members = GroupMember.query.filter_by(
        group_id=invitation.group_id,
        is_active=True
    ).filter(GroupMember.user_id != current_user.id).all()

    for group_member in group_members:
        notification = Notification(
            user_id=group_member.user_id,
            type='group_join',
            title='Nouveau membre dans le groupe',
            message=f'{current_user.username} a rejoint le groupe "{group.name}"',
            group_id=invitation.group_id,
            related_user_id=current_user.id
        )
        db.session.add(notification)

    db.session.commit()

    flash(f'Bienvenue dans le groupe "{group.name}" !', 'success')
    return redirect(url_for('groups'))

# Refuser une invitation depuis la page des groupes
@app.route('/reject_invitation/<int:invitation_id>')
@login_required
def reject_invitation_from_groups(invitation_id):
    invitation = Invitation.query.get_or_404(invitation_id)

    # Vérifier que l'invitation appartient à l'utilisateur actuel
    if invitation.invited_user_id != current_user.id:
        flash('Accès non autorisé', 'error')
        return redirect(url_for('groups'))

    if invitation.status != 'pending':
        flash('Cette invitation n\'est plus valide', 'error')
        return redirect(url_for('groups'))

    invitation.status = 'rejected'
    db.session.commit()

    group = Group.query.get(invitation.group_id)
    flash(f'Invitation pour le groupe "{group.name}" refusée', 'info')
    return redirect(url_for('groups'))

# Supprimer un membre
@app.route('/group/<int:group_id>/remove_member/<int:user_id>')
@login_required
def remove_member(group_id, user_id):
    group = Group.query.get_or_404(group_id)

    # Vérifier si l'utilisateur est admin
    is_admin = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id,
        is_admin=True
    ).first()

    if not is_admin and group.created_by != current_user.id:
        flash('Seuls les administrateurs peuvent supprimer des membres', 'error')
        return redirect(url_for('group_detail', group_id=group_id))

    if user_id == current_user.id:
        flash('Vous ne pouvez pas vous supprimer vous-même', 'error')
        return redirect(url_for('group_detail', group_id=group_id))

    member = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=user_id
    ).first()

    if member:
        member.is_active = False
        db.session.commit()
        flash('Membre supprimé du groupe', 'success')

    return redirect(url_for('group_detail', group_id=group_id))

# Ajouter une dépense de groupe
@app.route('/group/<int:group_id>/add_expense', methods=['GET', 'POST'])
@login_required
def add_group_expense(group_id):
    group = Group.query.get_or_404(group_id)

    # Vérifier si l'utilisateur est membre
    is_member = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id,
        is_active=True
    ).first()

    if not is_member:
        flash('Vous devez être membre du groupe pour ajouter des dépenses', 'error')
        return redirect(url_for('groups'))

    # Vérifier si le groupe est expiré
    if group.is_expired():
        flash('Ce groupe est expiré. Vous ne pouvez plus ajouter de dépenses.', 'warning')
        return redirect(url_for('group_detail', group_id=group_id))

    if request.method == 'POST':
        amount = float(request.form['amount'])
        category = request.form['category']
        description = request.form['description']
        expense_date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()

        # Gestion du fichier justificatif
        justificatif_filename = None
        if 'justificatif' in request.files:
            file = request.files['justificatif']
            if file and file.filename != '':
                # Vérifier l'extension du fichier
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
                if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                    # Générer un nom de fichier unique
                    import uuid
                    filename = str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower()
                    file_path = os.path.join(app.root_path, 'static', 'uploads', 'justificatifs', filename)
                    
                    # Créer le dossier s'il n'existe pas
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    
                    # Sauvegarder le fichier
                    file.save(file_path)
                    justificatif_filename = filename
                else:
                    flash('Type de fichier non autorisé. Seules les images (PNG, JPG, JPEG, GIF) et les PDF sont acceptés.', 'error')
                    return redirect(request.url)

        expense = Expense(
            amount=amount,
            category=category,
            description=description,
            date=expense_date,
            user_id=current_user.id,
            group_id=group_id,
            justificatif=justificatif_filename
        )

        db.session.add(expense)
        db.session.commit()

        # Créer une notification pour tous les membres du groupe (sauf l'utilisateur qui a ajouté la dépense)
        group_members = GroupMember.query.filter_by(
            group_id=group_id,
            is_active=True
        ).filter(GroupMember.user_id != current_user.id).all()

        for group_member in group_members:
            notification = Notification(
                user_id=group_member.user_id,
                type='group_expense',
                title='Nouvelle dépense dans le groupe',
                message=f'{current_user.username} a ajouté une dépense de {amount} DT dans "{group.name}"',
                group_id=group_id,
                related_user_id=current_user.id,
                expense_id=expense.id
            )
            db.session.add(notification)

        db.session.commit()

        flash('Dépense ajoutée au groupe avec succès!', 'success')
        return redirect(url_for('group_detail', group_id=group_id))

    return render_template('add_group_expense.html', group=group, categories=CATEGORIES, today=date.today())

# Notifications
@app.route('/notifications')
@login_required
def notifications():
    # Invitations en attente
    pending_invitations = Invitation.query.filter_by(
        invited_user_id=current_user.id,
        status='pending'
    ).join(Group).all()

    # Notifications récentes (non lues en premier, puis toutes les autres)
    notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).filter(
        ~Notification.type.in_(['group_invitation', 'group_join', 'group_expense'])  # Exclure toutes les notifications de groupe car elles sont affichées dans d'autres sections
    ).order_by(Notification.is_read.asc(), Notification.created_at.desc()).limit(20).all()

    # Compter les notifications non lues
    unread_count = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).count()

    # Groupes où l'utilisateur est membre
    user_groups = GroupMember.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).join(Group).all()

    return render_template('notifications.html',
                         pending_invitations=pending_invitations,
                         notifications=notifications,
                         unread_count=unread_count,
                         user_groups=user_groups)

# API pour marquer une notification comme lue
@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)

    # Vérifier que la notification appartient à l'utilisateur actuel
    if notification.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Accès non autorisé'})

    notification.is_read = True
    db.session.commit()

    return jsonify({'success': True})

# API pour marquer toutes les notifications comme lues
@app.route('/mark_all_notifications_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).update({'is_read': True})

    db.session.commit()

    return jsonify({'success': True})

# Paiements
@app.route('/payments')
@login_required
def payments():
    # Paiements simulés pour démonstration
    class MockPayment:
        def __init__(self, id, group_name, amount, description=None, status='pending'):
            self.id = id
            self.group_name = group_name
            self.amount = amount
            self.description = description or f'Paiement pour {group_name}'
            self.status = status
            self.paid_at = None
            self.group = MockGroup(group_name)

    class MockGroup:
        def __init__(self, name):
            self.name = name

    # Créer des paiements simulés
    pending_payments = [
        MockPayment(1, 'Soirée entre amis', 45.500, 'Participation aux boissons'),
        MockPayment(2, 'Voyage en Italie', 120.000, 'Remboursement essence'),
        MockPayment(3, 'Colocation', 200.000, 'Loyer du mois'),
    ]

    completed_payments = [
        MockPayment(4, 'Restaurant', 25.750, 'Addition du dîner', 'paid'),
        MockPayment(5, 'Cinéma', 15.000, 'Places de cinéma', 'paid'),
    ]

    # Vérifier le stockage temporaire pour les paiements traités
    for payment in pending_payments[:]:  # Copie de la liste pour éviter les modifications pendant l'itération
        if payment.id in payment_store and payment_store[payment.id]['status'] == 'paid':
            payment.status = 'paid'
            payment.paid_at = payment_store[payment.id]['paid_at']
            completed_payments.append(payment)
            pending_payments.remove(payment)

    # Marquer les paiements complétés avec une date
    import datetime
    for payment in completed_payments:
        if not hasattr(payment, 'paid_at') or payment.paid_at is None:
            payment.paid_at = datetime.datetime.now() - datetime.timedelta(days=2)

    all_payments = pending_payments + completed_payments
    total_paid = sum(p.amount for p in completed_payments)

    return render_template('payments.html',
                         pending_payments=pending_payments,
                         completed_payments=completed_payments,
                         all_payments=all_payments,
                         total_paid=total_paid)

# API pour marquer un paiement comme payé
@app.route('/payment/<int:payment_id>/mark-paid', methods=['POST'])
@login_required
def mark_payment_paid(payment_id):
    # Simulation - en production, ceci mettrait à jour la base de données
    return jsonify({'success': True})

# Stockage temporaire pour les paiements simulés (en production, ceci serait en base de données)
payment_store = {}

# API pour traiter un paiement automatique
@app.route('/payment/<int:payment_id>/process-payment', methods=['POST'])
@login_required
def process_payment(payment_id):
    try:
        data = request.get_json()

        # Validation des données de carte (simulation)
        card_number = data.get('card_number', '').replace(' ', '')
        expiry_date = data.get('expiry_date', '')
        cvv = data.get('cvv', '')
        card_holder = data.get('card_holder', '')

        # Validation basique
        if not card_number or len(card_number) != 16:
            return jsonify({'success': False, 'message': 'Numéro de carte invalide'})

        if not expiry_date or not cvv or not card_holder:
            return jsonify({'success': False, 'message': 'Informations de carte incomplètes'})

        # Simulation de traitement de paiement
        # En production, ceci serait intégré avec une passerelle de paiement comme Stripe, PayPal, etc.

        # Ici, on simule un paiement réussi
        import time
        time.sleep(1)  # Simulation de délai

        # Marquer le paiement comme payé dans le stockage temporaire
        payment_store[payment_id] = {
            'status': 'paid',
            'paid_at': datetime.datetime.now(),
            'transaction_id': f'TXN_{payment_id}_{int(time.time())}'
        }

        return jsonify({
            'success': True,
            'message': 'Paiement traité avec succès',
            'transaction_id': payment_store[payment_id]['transaction_id']
        })

    except Exception as e:
        return jsonify({'success': False, 'message': f'Erreur lors du traitement: {str(e)}'})

# API pour uploader un justificatif
@app.route('/upload-proof', methods=['POST'])
@login_required
def upload_proof():
    # Simulation d'upload de justificatif
    return jsonify({'success': True})

# Rapports avancés
@app.route('/advanced_reports')
@login_required
def advanced_reports():
    today = date.today()

    # Données pour les graphiques
    monthly_labels = []
    monthly_income = []
    monthly_expenses = []

    # Derniers 6 mois
    for i in range(5, -1, -1):
        month = today.month - i
        year = today.year
        if month <= 0:
            month += 12
            year -= 1

        month_inc = sum(inc.amount for inc in Income.query.filter(
            Income.user_id == current_user.id,
            db.extract('month', Income.date) == month,
            db.extract('year', Income.date) == year
        ).all())

        month_exp = sum(exp.amount for exp in Expense.query.filter(
            Expense.user_id == current_user.id,
            db.extract('month', Expense.date) == month,
            db.extract('year', Expense.date) == year
        ).all())

        monthly_labels.append(f"{month:02d}/{year}")
        monthly_income.append(month_inc)
        monthly_expenses.append(month_exp)

    # Données par catégorie
    all_expenses = Expense.query.filter_by(user_id=current_user.id).all()
    category_data = {}
    category_labels = []
    colors = ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF']

    for i, exp in enumerate(all_expenses):
        if exp.category in category_data:
            category_data[exp.category] += exp.amount
        else:
            category_data[exp.category] = exp.amount
            category_labels.append(exp.category)

    category_values = list(category_data.values())

    # Statistiques générales
    total_income = sum(inc.amount for inc in Income.query.filter(
        Income.user_id == current_user.id,
        db.extract('month', Income.date) == today.month,
        db.extract('year', Income.date) == today.year
    ).all())

    total_expenses = sum(exp.amount for exp in Expense.query.filter(
        Expense.user_id == current_user.id,
        db.extract('month', Expense.date) == today.month,
        db.extract('year', Expense.date) == today.year
    ).all())

    # Comptage des transactions
    income_count = Income.query.filter(
        Income.user_id == current_user.id,
        db.extract('month', Income.date) == today.month,
        db.extract('year', Income.date) == today.year
    ).count()

    expense_count = Expense.query.filter(
        Expense.user_id == current_user.id,
        db.extract('month', Expense.date) == today.month,
        db.extract('year', Expense.date) == today.year
    ).count()

    # Moyennes
    avg_income = total_income / income_count if income_count > 0 else 0
    avg_expense = total_expenses / expense_count if expense_count > 0 else 0

    current_balance = total_income - total_expenses

    # Croissances (simulées pour l'instant)
    income_growth = 5.2
    expense_growth = -2.1
    savings_rate = ((total_income - total_expenses) / total_income * 100) if total_income > 0 else 0
    balance_percentage = (current_balance / total_income * 100) if total_income > 0 else 0

    # Analyse par catégories
    category_analysis = []
    for i, (cat, amount) in enumerate(category_data.items()):
        category_analysis.append({
            'name': cat,
            'total': amount,
            'percentage': (amount / total_expenses * 100) if total_expenses > 0 else 0,
            'trend': 2.5,  # Simulé
            'monthly_avg': amount / 6,  # Simulé sur 6 mois
            'color': colors[i % len(colors)],
            'icon': 'utensils' if cat == 'Alimentation' else 'car' if cat == 'Transport' else 'home' if cat == 'Logement' else 'gamepad'
        })

    # Tendances
    trend_labels = monthly_labels
    trend_data = monthly_expenses

    # Recommandations
    recommendations = [
        {
            'title': 'Réduire les dépenses alimentaires',
            'description': 'Vos dépenses alimentaires représentent 35% de vos dépenses totales.',
            'impact': 'Économie potentielle: 150dt/mois',
            'type': 'warning',
            'icon': 'exclamation-triangle'
        },
        {
            'title': 'Augmenter le taux d\'épargne',
            'description': 'Votre taux d\'épargne actuel est de 15%. L\'objectif recommandé est de 20%.',
            'impact': 'Économie supplémentaire: 50dt/mois',
            'type': 'info',
            'icon': 'piggy-bank'
        }
    ]

    # Comparaisons
    income_comparison = 8.5  # Simulé
    expense_comparison = -3.2  # Simulé

    # Objectifs d'épargne (simulés)
    savings_goals = [
        {'name': 'Voyage d\'été', 'current': 450, 'target': 1200, 'progress': 37.5},
        {'name': 'Fonds d\'urgence', 'current': 2500, 'target': 5000, 'progress': 50}
    ]

    # Catégories pour les filtres
    categories = list(set(exp.category for exp in all_expenses))

    # Groupes de l'utilisateur
    user_groups = GroupMember.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).join(Group).all()

    return render_template('advanced_reports.html',
                         monthly_labels=monthly_labels,
                         monthly_income=monthly_income,
                         monthly_expenses=monthly_expenses,
                         category_labels=category_labels,
                         category_data=category_values,
                         category_colors=colors[:len(category_labels)],
                         total_income=total_income,
                         total_expenses=total_expenses,
                         income_count=income_count,
                         expense_count=expense_count,
                         avg_income=avg_income,
                         avg_expense=avg_expense,
                         balance=current_balance,
                         income_growth=income_growth,
                         expense_growth=expense_growth,
                         savings_rate=savings_rate,
                         balance_percentage=balance_percentage,
                         category_analysis=category_analysis,
                         trend_labels=trend_labels,
                         trend_data=trend_data,
                         recommendations=recommendations,
                         income_comparison=income_comparison,
                         expense_comparison=expense_comparison,
                         savings_goals=savings_goals,
                         categories=categories,
                         user_groups=user_groups)

# Paramètres
@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

# API pour mettre à jour le profil
@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    current_user.first_name = request.form.get('first_name', '')
    current_user.last_name = request.form.get('last_name', '')
    current_user.email = request.form.get('email', current_user.email)
    current_user.phone = request.form.get('phone', '')
    current_user.bio = request.form.get('bio', '')

    db.session.commit()
    return jsonify({'success': True})

# API pour changer le mot de passe
@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']

    if not check_password_hash(current_user.password_hash, current_password):
        return jsonify({'success': False, 'message': 'Mot de passe actuel incorrect'})

    current_user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    return jsonify({'success': True})

# API pour mettre à jour les notifications
@app.route('/update-notifications', methods=['POST'])
@login_required
def update_notifications():
    # Ici on pourrait sauvegarder les préférences de notifications
    # Pour l'instant, on simule juste une réponse positive
    return jsonify({'success': True})

# API pour mettre à jour les préférences
@app.route('/update-preferences', methods=['POST'])
@login_required
def update_preferences():
    # Ici on pourrait sauvegarder les préférences générales
    # Pour l'instant, on simule juste une réponse positive
    return jsonify({'success': True})

# API pour désactiver 3fA
@app.route('/disable-3fa', methods=['POST'])
@login_required
def disable_3fa():
    # Simulation de désactivation 3fA
    return jsonify({'success': True})

# API pour exporter les données
@app.route('/export-data')
@login_required
def export_data():
    # Simulation d'export de données
    data = {
        'user': {
            'username': current_user.username,
            'created_at': current_user.created_at.isoformat()
        },
        'expenses': [{'amount': exp.amount, 'category': exp.category, 'date': exp.date.isoformat()}
                    for exp in Expense.query.filter_by(user_id=current_user.id).all()],
        'incomes': [{'amount': inc.amount, 'category': inc.category, 'date': inc.date.isoformat()}
                   for inc in Income.query.filter_by(user_id=current_user.id).all()]
    }
    return jsonify(data)

# API pour supprimer le compte
@app.route('/delete-account', methods=['DELETE'])
@login_required
def delete_account():
    # Simulation de suppression de compte
    # En réalité, il faudrait implémenter une suppression sécurisée
    return jsonify({'success': True})

# Profil utilisateur
@app.route('/profile')
@login_required
def profile():
    # Statistiques de l'utilisateur
    total_expenses = sum(exp.amount for exp in Expense.query.filter_by(user_id=current_user.id).all())

    # Groupes de l'utilisateur
    user_groups = GroupMember.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).join(Group).all()

    # Dernières dépenses
    user_expenses = Expense.query.filter_by(user_id=current_user.id).order_by(Expense.date.desc()).limit(10).all()

    # Invitations envoyées
    sent_invitations = Invitation.query.filter_by(sender_id=current_user.id).join(Group).all()

    return render_template('profile.html',
                         user=current_user,
                         total_expenses=total_expenses,
                         groups=user_groups,
                         expenses=user_expenses,
                         sent_invitations=sent_invitations)

# Tarification
@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

# Mise à niveau vers Premium avec essai gratuit
@app.route('/upgrade_to_premium')
@login_required
def upgrade_to_premium():
    # Activer l'essai gratuit de 30 jours
    if not current_user.is_trial_active() and current_user.plan_type != 'premium':
        current_user.start_trial(30)
        db.session.commit()
        flash('Votre essai gratuit Premium de 30 jours a été activé ! Profitez de toutes les fonctionnalités premium.', 'success')
    elif current_user.is_trial_active():
        flash('Votre essai gratuit Premium est déjà actif !', 'info')
    else:
        flash('Vous avez déjà accès au plan Premium.', 'info')
    
    return redirect(url_for('dashboard'))

# Context processor pour les variables globales
@app.context_processor
def inject_global_vars():
    if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
        unread_count = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).count()
    else:
        unread_count = 0
    
    return dict(unread_count=unread_count)

if __name__ == '__main__':
    import sys
    port = 5000
    if len(sys.argv) > 1 and sys.argv[1] == '--port':
        try:
            port = int(sys.argv[2])
        except (IndexError, ValueError):
            pass
    app.run(debug=True, port=port)