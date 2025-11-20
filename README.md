# Gestion Budget Personnel

Une application Flask pour la gestion des budgets personnels avec fonctionnalités de groupes et paiements.

## Configuration OAuth

L'application prend en charge l'authentification via Google et Facebook. Pour configurer ces services, vous devez obtenir des clés API auprès de chaque plateforme.

### 1. Configuration Google OAuth

1. **Accédez à Google Cloud Console** :
   - Allez sur [https://console.developers.google.com/](https://console.developers.google.com/)
   - Créez un nouveau projet ou sélectionnez-en un existant

2. **Activez les APIs nécessaires** :
   - Activez l'API "Google+ API" ou "Google People API"

3. **Créez des identifiants OAuth 2.0** :
   - Dans le menu latéral, allez dans "Identifiants"
   - Cliquez sur "Créer des identifiants" > "ID client OAuth"
   - Choisissez "Application Web"
   - Ajoutez `http://localhost:5000/login/google/authorize` comme URI de redirection autorisée

4. **Récupérez vos clés** :
   - Copiez le "Client ID" et le "Client Secret"

### 2. Configuration Facebook OAuth

1. **Accédez aux développeurs Facebook** :
   - Allez sur [https://developers.facebook.com/](https://developers.facebook.com/)
   - Créez une nouvelle app Facebook

2. **Configurez Facebook Login** :
   - Dans les paramètres de votre app, allez dans "Facebook Login"
   - Ajoutez `http://localhost:5000/login/facebook/authorize` comme URI de redirection OAuth valide

3. **Récupérez vos clés** :
   - Copiez l'"App ID" et l'"App Secret"

### 3. Configuration des variables d'environnement

1. **Copiez le fichier d'exemple** :
   ```bash
   cp .env.example .env
   ```

2. **Modifiez le fichier `.env`** avec vos vraies clés :
   ```env
   GOOGLE_CLIENT_ID=votre_vrai_google_client_id
   GOOGLE_CLIENT_SECRET=votre_vrai_google_client_secret
   FACEBOOK_CLIENT_ID=votre_vrai_facebook_app_id
   FACEBOOK_CLIENT_SECRET=votre_vrai_facebook_app_secret
   ```

### 4. Installation et lancement

1. **Installez les dépendances** :
   ```bash
   pip install -r requirements.txt
   ```

2. **Lancez l'application** :
   ```bash
   python app.py
   ```

3. **Accédez à l'application** :
   - Ouvrez votre navigateur à `http://localhost:5000`
   - Cliquez sur "Se connecter avec Google" ou "Se connecter avec Facebook"

## Fonctionnalités

- ✅ Gestion des dépenses et revenus personnels
- ✅ Création et gestion de groupes
- ✅ Système d'invitations pour les groupes
- ✅ Authentification OAuth (Google & Facebook)
- ✅ Système de notifications
- ✅ Paiements simulés
- ✅ Rapports et statistiques avancés

## Technologies utilisées

- **Backend** : Flask, SQLAlchemy, Flask-Login
- **Authentification** : Authlib (OAuth 2.0)
- **Base de données** : SQLite
- **Frontend** : Bootstrap 5, JavaScript
- **Analyse** : NLTK pour le traitement du langage naturel

## Structure du projet

```
gestion-budget-personnel/
├── app.py                 # Application principale Flask
├── models.py             # Modèles de base de données
├── requirements.txt      # Dépendances Python
├── .env                  # Variables d'environnement (à créer)
├── .env.example          # Exemple de configuration
├── static/               # Fichiers statiques (CSS, JS, images)
├── templates/            # Templates HTML
└── instance/             # Base de données SQLite
```

## Dépannage OAuth

### Erreur "The OAuth client was not found" (Google)
- Vérifiez que votre Client ID Google est correct
- Assurez-vous que l'URI de redirection `http://localhost:5000/login/google/authorize` est configurée dans Google Cloud Console

### Erreur "ID d'app non valide" (Facebook)
- Vérifiez que votre App ID Facebook est correct
- Assurez-vous que l'URI de redirection `http://localhost:5000/login/facebook/authorize` est configurée dans les paramètres Facebook Login

### Erreur 500 lors de la connexion OAuth
- Vérifiez que les variables d'environnement sont correctement chargées
- Assurez-vous que python-dotenv est installé : `pip install python-dotenv`

## Sécurité

⚠️ **Important** : Cette application est configurée pour le développement local. En production :
- Utilisez HTTPS
- Stockez les clés API dans des variables d'environnement sécurisées
- Configurez des URIs de redirection de production
- Implémentez une gestion d'erreurs appropriée