import sqlite3

conn = sqlite3.connect('transfert.db')
c = conn.cursor()

c.execute("SELECT * FROM users")
users = c.fetchall()

print("Utilisateurs enregistrés :")
for user in users:
    print(f"ID: {user[0]}, Nom: {user[1]}, Email: {user[2]}, Mot de passe: {user[3]}")

conn.close()