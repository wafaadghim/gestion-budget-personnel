# Configuration OAuth pour Google et Facebook

## Configuration Google OAuth

1. Allez sur [Google Cloud Console](https://console.cloud.google.com/)
2. Créez un nouveau projet ou sélectionnez un projet existant
3. Activez l'API Google+ (ou Google People API)
4. Créez des identifiants OAuth 2.0 :
   - Type : Application Web
   - URI de redirection autorisée : `http://localhost:5000/login/google/authorize` (pour le développement)
5. Copiez l'ID client et le secret client
6. Remplacez les valeurs dans `app.py` :
   ```python
   app.config['GOOGLE_CLIENT_ID'] = 'votre_google_client_id'
   app.config['GOOGLE_CLIENT_SECRET'] = 'votre_google_client_secret'
   ```

## Configuration Facebook OAuth

1. Allez sur [Facebook Developers](https://developers.facebook.com/)
2. Créez une nouvelle app ou sélectionnez une app existante
3. Ajoutez le produit "Facebook Login"
4. Dans les paramètres de Facebook Login :
   - URI de redirection OAuth valides : `http://localhost:5000/login/facebook/authorize` (pour le développement)
5. Copiez l'ID de l'app et le secret de l'app
6. Remplacez les valeurs dans `app.py` :
   ```python
   app.config['FACEBOOK_CLIENT_ID'] = 'votre_facebook_app_id'
   app.config['FACEBOOK_CLIENT_SECRET'] = 'votre_facebook_app_secret'
   ```

## Utilisation

Une fois configuré, les utilisateurs peuvent se connecter en cliquant sur les boutons "Google" ou "Facebook" sur la page de connexion.

## Sécurité

- En production, utilisez HTTPS
- Configurez les URI de redirection appropriées pour votre domaine
- Gardez les secrets client sécurisés (variables d'environnement)