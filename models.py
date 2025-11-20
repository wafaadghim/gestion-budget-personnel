from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, time, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    phone_number = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Champs pour les plans premium
    plan_type = db.Column(db.String(20), default='free')  # 'free' ou 'premium'
    trial_start_date = db.Column(db.DateTime, nullable=True)
    trial_end_date = db.Column(db.DateTime, nullable=True)
    
    # Relations
    expenses = db.relationship('Expense', backref='user', lazy=True)
    budgets = db.relationship('Budget', backref='user', lazy=True)
    incomes = db.relationship('Income', backref='user', lazy=True)
    groups_created = db.relationship('Group', backref='creator', lazy=True)
    group_memberships = db.relationship('GroupMember', backref='user', lazy=True)
    invitations_sent = db.relationship('Invitation', foreign_keys='Invitation.sender_id', backref='sender', lazy=True)
    invitations_received = db.relationship('Invitation', foreign_keys='Invitation.invited_user_id', backref='invited_user', lazy=True)
    notifications = db.relationship('Notification', foreign_keys='Notification.user_id', backref='recipient', lazy=True)
    triggered_notifications = db.relationship('Notification', foreign_keys='Notification.related_user_id', backref='trigger_user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_premium(self):
        """Vérifie si l'utilisateur a un plan premium actif"""
        if self.plan_type == 'premium':
            return True
        
        # Vérifier si l'essai gratuit est actif
        if self.plan_type == 'free' and self.trial_end_date:
            return datetime.utcnow() <= self.trial_end_date
        
        return False
    
    def is_trial_active(self):
        """Vérifie si l'utilisateur est en période d'essai"""
        if self.trial_end_date and self.plan_type == 'free':
            return datetime.utcnow() <= self.trial_end_date
        return False
    
    def start_trial(self, days=30):
        """Démarre un essai gratuit de X jours"""
        now = datetime.utcnow()
        self.trial_start_date = now
        self.trial_end_date = now + timedelta(days=days)
        self.plan_type = 'free'  # L'essai est sur le plan free
    
    def upgrade_to_premium(self):
        """Met à niveau vers le plan premium"""
        self.plan_type = 'premium'
        # Conserver les dates d'essai pour l'historique si nécessaire

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    location = db.Column(db.String(200))  # Lieu de rencontre
    date_sortie = db.Column(db.Date)
    heure_sortie = db.Column(db.Time)
    nombre_jours = db.Column(db.Integer, default=1)  # Nombre de jours pour la durée du groupe
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    invite_token = db.Column(db.String(64), unique=True, nullable=True)  # Token permanent pour les invitations
    
    # Relations
    members = db.relationship('GroupMember', backref='group', lazy=True)
    expenses = db.relationship('Expense', backref='group', lazy=True)
    invitations = db.relationship('Invitation', backref='group', lazy=True)
    
    def is_expired(self):
        today = date.today()
        
        # Si une date de sortie spécifique est définie
        if self.date_sortie:
            if today > self.date_sortie:
                return True
            elif today == self.date_sortie and self.heure_sortie:
                now = datetime.now().time()
                return now > self.heure_sortie
        
        # Si un nombre de jours est défini, vérifier par rapport à la date de création
        elif self.nombre_jours and self.nombre_jours > 0:
            expiration_date = self.created_at.date() + timedelta(days=self.nombre_jours)
            if today > expiration_date:
                return True
        
        return False

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)  # Nouveau champ pour les administrateurs
    
    # Relation unique
    __table_args__ = (db.UniqueConstraint('group_id', 'user_id', name='unique_group_member'),)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='autre')
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    justificatif = db.Column(db.String(255), nullable=True)  # Chemin vers le fichier justificatif (image/PDF)

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    month = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    date = db.Column(db.Date, nullable=False, default=date.today)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Invitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invited_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=True)  # Token pour les invitations par email
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    email = db.Column(db.String(120), nullable=True)  # Email de l'invité (si pas encore utilisateur)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)  # Date d'expiration de l'invitation
    
    # Relations
    __table_args__ = (db.UniqueConstraint('group_id', 'invited_user_id', name='unique_group_invitation'),)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # 'group_join', 'group_expense', 'invitation', etc.
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    related_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # User who triggered the notification
    expense_id = db.Column(db.Integer, db.ForeignKey('expense.id'), nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relations
    user = db.relationship('User', foreign_keys=[user_id])
    group = db.relationship('Group', backref='notifications')
    related_user = db.relationship('User', foreign_keys=[related_user_id])
    expense = db.relationship('Expense', backref='notifications')