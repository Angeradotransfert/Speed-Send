import bcrypt
import sqlite3


def is_password_hashed(password):
    # Vérifier si le mot de passe a le bon format de hachage bcrypt
    return password.startswith('$2b$') and len(password) == 60  # Le hachage bcrypt est toujours de 60 caractères


def hash_and_update_password(user_id, new_password):
    # Hacher le mot de passe
    hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    # Connexion à la base de données
    conn = sqlite3.connect('transfert.db')  # Assurez-vous que votre fichier de base de données est correct
    c = conn.cursor()

    # Mettre à jour le mot de passe haché
    c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_pw, user_id))
    conn.commit()
    conn.close()
    print(f"Mot de passe mis à jour pour l'utilisateur {user_id}")


def check_and_update_passwords():
    # Connexion à la base de données
    conn = sqlite3.connect('transfert.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Récupérer tous les utilisateurs de la base de données
    c.execute("SELECT id, password FROM users")
    users = c.fetchall()

    # Parcourir chaque utilisateur pour vérifier leur mot de passe
    for user in users:
        user_id = user['id']
        password = user['password']

        # Vérifier si le mot de passe est déjà haché
        if not is_password_hashed(password):
            print(f"Utilisateur {user_id} a un mot de passe en clair, mise à jour en cours...")
            # Si le mot de passe n'est pas haché, on le hache et met à jour l'utilisateur
            hash_and_update_password(user_id, password)

    conn.close()


# Appel de la fonction pour vérifier et mettre à jour les mots de passe
check_and_update_passwords()
