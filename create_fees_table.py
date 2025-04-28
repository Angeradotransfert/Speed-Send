import sqlite3

# Connexion à ta base transfert.db
conn = sqlite3.connect('transfert.db')
c = conn.cursor()

# Créer la table si elle n'existe pas
c.execute('''
CREATE TABLE IF NOT EXISTS fees_and_rates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_country TEXT,
    destination_country TEXT,
    rate REAL,
    fee REAL,
    fee_currency TEXT
)
''')

conn.commit()
conn.close()

print("✅ Table 'fees_and_rates' créée avec succès !")
