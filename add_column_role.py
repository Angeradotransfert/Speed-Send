import sqlite3

# Connexion à la base de données
conn = sqlite3.connect('transfert.db')
c = conn.cursor()

# Ajouter la colonne 'role' si elle n'existe pas déjà
try:
    c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';")
    print("Colonne 'role' ajoutée avec succès.")
except sqlite3.OperationalError:
    print("La colonne 'role' existe déjà.")

conn.commit()
conn.close()
