import sqlite3

def promote_to_admin(email):
    conn = sqlite3.connect('transfert.db')
    c = conn.cursor()

    # Modifier le rôle de l'utilisateur
    c.execute("UPDATE users SET role = ? WHERE email = ?", ('admin', email))

    conn.commit()
    conn.close()

    print(f"L'utilisateur {email} a été promu administrateur.")

if __name__ == "__main__":
    email = "konea3873@gmail.com"  # Remplace ceci par l'email de l'utilisateur à promouvoir
    promote_to_admin(email)
