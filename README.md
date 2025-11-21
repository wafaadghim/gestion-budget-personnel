# Gestion Budget Personnel

Une application web complète de gestion budgétaire personnelle et collaborative développée avec Flask. Permet aux utilisateurs de suivre leurs dépenses et revenus, créer des groupes pour partager des dépenses communes, et générer des rapports financiers avancés.

## 🚀 Fonctionnalités Principales

### 💰 Gestion Financière Personnelle
- **Suivi des dépenses et revenus** avec montants précis en dinars tunisiens (3 décimales)
- **Catégorisation automatique** des dépenses via NLP (Natural Language Processing)
- **Gestion des justificatifs** avec upload de fichiers
- **Filtrage avancé** par période (année, mois, personnalisée) et catégorie

### 👥 Gestion de Groupes Collaboratifs
- **Création de groupes** avec date/heure de création et expiration
- **Système d'invitations** avec acceptation/refus par email
- **Calcul automatique des parts** pour chaque membre
- **Gestion des balances** : qui doit payer/recevoir combien
- **Dépenses de groupe** avec répartition équitable

### 📊 Rapports et Analyses Avancés
- **Tableau de bord financier** avec métriques clés (revenus, dépenses, solde, taux d'épargne)
- **Analyse temporelle** avec graphiques d'évolution mensuelle
- **Analyse par catégories** avec tendances et moyennes
- **Filtres dynamiques** : période et catégorie sélectionnables
- **Statistiques détaillées** : ratios financiers, comparaisons périodiques

### 🔐 Authentification et Sécurité
- **Authentification OAuth** (Google & Facebook)
- **Système de mots de passe** sécurisé avec hachage
- **Gestion des sessions** utilisateur
- **Protection CSRF** sur les formulaires

### 📱 Interface Utilisateur
- **Design responsive** avec Bootstrap 5
- **Interface moderne** et intuitive
- **Graphiques interactifs** avec Chart.js
- **Notifications en temps réel**
- **Thème sombre/clair** adaptable

## 🛠️ Technologies Utilisées

### Backend
- **Flask 2.3.3** - Framework web Python
- **SQLAlchemy 3.0.5** - ORM pour base de données
- **Flask-Login 0.6.3** - Gestion des sessions utilisateur
- **Authlib 1.2.1** - Authentification OAuth 2.0

### Intelligence Artificielle
- **NLTK 3.8.1** - Traitement du langage naturel
- **scikit-learn 1.3.0** - Algorithmes de machine learning pour catégorisation

### Frontend
- **Bootstrap 5** - Framework CSS responsive
- **Chart.js** - Graphiques interactifs
- **JavaScript ES6** - Interactivité côté client
- **Font Awesome** - Icônes vectorielles

### Base de Données
- **SQLite** - Base de données légère et portable
- **Alembic** - Gestion des migrations de base de données

## 📁 Structure du Projet

```
gestion-budget-personnel/
├── app.py                          # Application Flask principale
├── models.py                       # Modèles de base de données SQLAlchemy
├── requirements.txt                # Dépendances Python
├── OAUTH_SETUP.md                  # Guide configuration OAuth
├── fonctionnalites.txt             # Liste des fonctionnalités
├── structure.txt                   # Structure du projet
├── cookies.txt                     # Configuration cookies (dev)
├── twilio_2FA_recovery_code.txt    # Codes 2FA (dev)
├── update_group_tokens.py          # Script mise à jour tokens
├── static/                         # Fichiers statiques
│   ├── css/
│   │   └── style.css              # Styles personnalisés
│   ├── js/
│   │   └── script.js              # JavaScript frontend
│   └── uploads/
│       └── justificatifs/         # Uploads de fichiers
├── templates/                      # Templates Jinja2
│   ├── base.html                  # Template de base
│   ├── index.html                 # Page d'accueil
│   ├── login.html                 # Connexion
│   ├── register.html              # Inscription
│   ├── dashboard.html             # Tableau de bord
│   ├── advanced_reports.html      # Rapports avancés
│   ├── create_group.html          # Création de groupe
│   ├── group_detail.html          # Détails du groupe
│   ├── groups.html                # Liste des groupes
│   ├── invitations.html           # Invitations
│   ├── profile.html               # Profil utilisateur
│   ├── expenses.html              # Gestion des dépenses
│   ├── incomes.html               # Gestion des revenus
│   ├── add_expense.html           # Ajout de dépense
│   ├── add_income.html            # Ajout de revenu
│   ├── edit_expense.html          # Modification dépense
│   ├── edit_income.html           # Modification revenu
│   ├── balance.html               # Balances des groupes
│   ├── reports.html               # Rapports simples
│   ├── settings.html              # Paramètres
│   ├── notifications.html         # Notifications
│   └── payments.html              # Paiements simulés
├── instance/                       # Base de données SQLite
├── migrations/                     # Migrations Alembic
│   ├── alembic.ini
│   ├── env.py
│   ├── README
│   ├── script.py.mako
│   └── versions/                   # Scripts de migration
└── __pycache__/                    # Cache Python
```

## 🚀 Installation et Configuration

### Prérequis
- **Python 3.8+**
- **pip** (gestionnaire de paquets Python)
- **Navigateur web moderne**

### 1. Clonage du Repository
```bash
git clone https://github.com/wafaadghim/gestion-budget-personnel.git
cd gestion-budget-personnel
```

### 2. Installation des Dépendances
```bash
pip install -r requirements.txt
```

### 3. Configuration OAuth (Optionnel)
Pour activer l'authentification Google/Facebook :

1. **Copiez le fichier d'exemple** :
   ```bash
   cp .env.example .env
   ```

2. **Configurez OAuth** selon le guide `OAUTH_SETUP.md`

3. **Variables d'environnement** :
   ```env
   GOOGLE_CLIENT_ID=votre_google_client_id
   GOOGLE_CLIENT_SECRET=votre_google_client_secret
   FACEBOOK_CLIENT_ID=votre_facebook_app_id
   FACEBOOK_CLIENT_SECRET=votre_facebook_app_secret
   ```

### 4. Initialisation de la Base de Données
```bash
# Créer les tables
python -c "from app import app, db; app.app_context().push(); db.create_all()"

# Ou utiliser les migrations Alembic
flask db init
flask db migrate
flask db upgrade
```

### 5. Lancement de l'Application
```bash
python app.py
```

### 6. Accès à l'Application
- Ouvrez votre navigateur à `http://localhost:5000`
- Créez un compte ou connectez-vous avec OAuth

## 📊 Fonctionnalités Détaillées

### Gestion des Dépenses et Revenus
- **Ajout manuel** avec description et catégorie
- **Catégorisation automatique** via NLP
- **Upload de justificatifs** (factures, reçus)
- **Modification et suppression** des transactions
- **Filtrage par période** et catégorie

### Gestion des Groupes
- **Création de groupes** avec nom, description et date d'expiration
- **Invitations par email** avec tokens sécurisés
- **Acceptation/refus** des invitations
- **Calcul automatique** des parts et balances
- **Dépenses partagées** avec répartition équitable

### Rapports Financiers Avancés
- **Tableau de bord** avec métriques clés :
  - Revenus totaux et dépenses totales
  - Solde net et taux d'épargne
  - Nombre de transactions
  - Moyennes par transaction
- **Analyse temporelle** avec graphiques d'évolution
- **Analyse par catégories** avec tendances
- **Filtres dynamiques** par période et catégorie
- **Export de rapports** (fonctionnalité à implémenter)

### Système de Notifications
- **Notifications en temps réel** pour les invitations
- **Alertes de groupe** (expiration, nouveaux membres)
- **Rappels de paiement** pour les balances dues

## 🔧 Développement et Contribution

### Scripts Utiles
```bash
# Vérifier l'import de l'application
python -c "from app import app; print('✅ Import réussi')"

# Créer un utilisateur de test
python -c "
from app import app, db
from models import User
with app.app_context():
    user = User(username='test', email='test@example.com')
    user.set_password('password')
    db.session.add(user)
    db.session.commit()
    print('✅ Utilisateur test créé')
"

# Lancer en mode debug
FLASK_DEBUG=1 python app.py
```

### Tests et Validation
```bash
# Tester la syntaxe des templates
python -c "
import jinja2
from jinja2 import Template
try:
    with open('templates/advanced_reports.html', 'r', encoding='utf-8') as f:
        Template(f.read())
    print('✅ Templates valides')
except Exception as e:
    print(f'❌ Erreur template: {e}')
"
```

## 🔒 Sécurité

### Mesures Implémentées
- **Hachage des mots de passe** avec Werkzeug
- **Protection CSRF** sur tous les formulaires
- **Validation des entrées** côté serveur
- **Échappement HTML** automatique (Jinja2)
- **Sessions sécurisées** avec secrets

### Recommandations Production
- Utiliser **HTTPS** obligatoire
- Configurer un **pare-feu** (firewall)
- **Mettre à jour régulièrement** les dépendances
- **Sauvegarder régulièrement** la base de données
- Utiliser des **variables d'environnement** pour les secrets

## 🐛 Dépannage

### Erreurs Courantes

#### Erreur OAuth
```
The OAuth client was not found
```
**Solution** : Vérifiez les clés API et URIs de redirection dans la console développeur

#### Erreur Base de Données
```
sqlalchemy.exc.OperationalError
```
**Solution** : Vérifiez les permissions du dossier `instance/` et relancez les migrations

#### Erreur Import NLTK
```
Resource punkt not found
```
**Solution** :
```bash
python -c "import nltk; nltk.download('punkt')"
```

### Logs et Debug
```bash
# Activer les logs détaillés
export FLASK_DEBUG=1
python app.py

# Vérifier les processus
ps aux | grep python

# Tuer les processus bloquants
pkill -f "python app.py"
```

## 📈 Évolutions Récentes

### Version Actuelle (2025)
- ✅ **Réorganisation complète** de la page rapports avancés
- ✅ **Suppression des sections** "Tendances et Prévisions" et "Recommandations"
- ✅ **Filtrage réel** des données selon période et catégorie
- ✅ **Calculs dynamiques** des métriques financières
- ✅ **Interface épurée** avec focus sur l'essentiel
- ✅ **Corrections de format** de date (DD/MM/YYYY)
- ✅ **Optimisation des performances** et stabilité

### Fonctionnalités à Venir
- 🔄 **Export PDF/Excel** des rapports
- 🔄 **API REST** pour intégrations tierces
- 🔄 **Application mobile** React Native
- 🔄 **Synchronisation cloud** des données
- 🔄 **Intelligence artificielle** prédictive pour budgets

## 📞 Support et Contact

Pour toute question ou problème :
- **Issues GitHub** : [Créer une issue](https://github.com/wafaadghim/gestion-budget-personnel/issues)
- **Documentation** : Consultez les fichiers `OAUTH_SETUP.md` et `fonctionnalites.txt`

---

**Développé avec ❤️ par Wafa Adghim**