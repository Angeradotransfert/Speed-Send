import sqlite3

def delete_user(email):
    # Connexion à la base de données
    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()

    # Supprimer l'utilisateur de la table users
    c.execute("DELETE FROM users WHERE email = ?", (email,))

    # Supprimer les informations associées à l'utilisateur dans d'autres tables (par exemple les wallets, transactions, etc.)
    c.execute("DELETE FROM wallets WHERE user_id IN (SELECT id FROM users WHERE email = ?)", (email,))
    c.execute("DELETE FROM transactions WHERE sender_id IN (SELECT id FROM users WHERE email = ?)", (email,))
    c.execute("DELETE FROM transactions WHERE recipient_id IN (SELECT id FROM users WHERE email = ?)", (email,))
    c.execute("DELETE FROM external_transfers WHERE sender_id IN (SELECT id FROM users WHERE email = ?)", (email,))
    c.execute("DELETE FROM pending_transfers WHERE sender_name = ?", (email,))

    conn.commit()
    conn.close()

    print(f"L'utilisateur avec l'email {email} a été supprimé avec succès.")

if __name__ == "__main__":
    email = "angerdotransfert@gmail.com"  # Remplace cet email par celui de l'utilisateur que tu veux supprimer
    delete_user(email)
