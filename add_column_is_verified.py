import sqlite3

def add_column_if_not_exists(db_name, table_name, column_name, column_type):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()

    # Vérifie la structure actuelle de la table
    c.execute(f"PRAGMA table_info({table_name})")
    columns = [info[1] for info in c.fetchall()]

    if column_name not in columns:
        try:
            c.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
            print(f"✅ Colonne '{column_name}' ajoutée à la table '{table_name}'.")
        except sqlite3.OperationalError as e:
            print(f"❌ Erreur pendant l'ajout : {e}")
    else:
        print(f"ℹ️ La colonne '{column_name}' existe déjà.")

    conn.commit()
    conn.close()

# Ajoute la colonne is_verified (de type INTEGER pour 0 ou 1)
add_column_if_not_exists('transfert.db', 'users', 'is_verified', 'INTEGER DEFAULT 0')
