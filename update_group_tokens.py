#!/usr/bin/env python3
"""
Script pour mettre à jour les groupes existants avec des tokens d'invitation permanents.
À exécuter une seule fois après la migration de la base de données.
"""

import os
import sys
import secrets

# Ajouter le répertoire du projet au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import Group

def update_existing_groups():
    """Met à jour tous les groupes existants avec des tokens d'invitation uniques."""

    with app.app_context():
        groups = Group.query.filter(Group.invite_token.is_(None)).all()

        if not groups:
            print("Tous les groupes ont déjà des tokens d'invitation.")
            return

        print(f"Mise à jour de {len(groups)} groupes...")

        for group in groups:
            # Générer un token unique
            token = secrets.token_urlsafe(32)

            # S'assurer que le token est unique
            while Group.query.filter_by(invite_token=token).first():
                token = secrets.token_urlsafe(32)

            group.invite_token = token
            print(f"Token généré pour le groupe '{group.name}': {token[:10]}...")

        try:
            db.session.commit()
            print(f"Succès : {len(groups)} groupes mis à jour avec des tokens d'invitation.")
        except Exception as e:
            db.session.rollback()
            print(f"Erreur lors de la mise à jour : {e}")
            sys.exit(1)

if __name__ == "__main__":
    update_existing_groups()