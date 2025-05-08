import sqlite3
from datetime import datetime, timedelta

# Connexion à la base de données
conn = sqlite3.connect('transfert.db')
c = conn.cursor()

# Heure limite (il y a 10 minutes)
now = datetime.now()
limite = now - timedelta(minutes=10)
limite_str = limite.strftime("%Y-%m-%d %H:%M:%S")

# Suppression des transferts expirés
c.execute('''
    DELETE FROM pending_transfers
    WHERE status = 'en_attente' AND created_at <= ?
''', (limite_str,))

conn.commit()
conn.close()

print("🗑️ Transferts expirés supprimés définitivement.")
