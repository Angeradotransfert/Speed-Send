from time import sleep
import requests
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from PIL import Image, ImageTk
from io import BytesIO

# Fonction pour récupérer et afficher les logos
def get_team_logo(team_id):
    url = f"https://api.football-data.org/v4/teams/{team_id}"
    headers = {"X-Auth-Token": API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            logo_url = response.json().get('crest')
            if logo_url:
                logo_response = requests.get(logo_url)
                img_data = Image.open(BytesIO(logo_response.content))
                img_data = img_data.resize((50, 50), Image.ANTIALIAS)
                return ImageTk.PhotoImage(img_data)
    except Exception as e:
        print(f"Erreur lors du téléchargement du logo: {e}")
    return None


API_KEY = "e2e36148382c4406855bbbdb53d7b55c"
BASE_URL = "https://api.football-data.org/v4/competitions"
HEADERS = {"X-Auth-Token": API_KEY}

# Liste des compétitions avec leurs codes
COMPETITIONS = {
    "PL": "PL",  # Premier League
    "FL1": "FL1",  # Ligue 1
    "BL1": "BL1",  # Bundesliga
    "SA": "SA",  # Serie A
    "PD": "PD"  # La Liga
}


def get_all_competitions():
    url = f"{BASE_URL}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        data = response.json()
        # Afficher les compétitions disponibles avec leurs ids
        print("Compétitions disponibles :")
        competitions = {}
        for competition in data['competitions']:
            print(f"{competition['name']} ({competition['code']})")
            competitions[competition['code']] = competition['id']
        return competitions
    else:
        print(f"Erreur lors de la récupération des compétitions: {response.status_code}, {response.text}")
        return {}


def get_matches(competition_code):
    url = f"{BASE_URL}/{competition_code}/matches"
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        matches = response.json().get('matches', [])
        print(f"Réponse pour {competition_code}: {len(matches)} matchs récupérés")
        return matches
    else:
        print(f"Réponse pour {competition_code}: {response.status_code}")
        return []


class FootballApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Pronos Football - Avec Logos")
        self.root.geometry("1100x700")
        self.root.configure(bg="#1e1e2f")

        self.button = tk.Button(root, text="Générer les pronostics", command=self.generer,
                                font=("Helvetica", 12, "bold"),
                                bg="#00cc99", fg="white", relief="flat", padx=10, pady=5)
        self.button.pack(pady=10)

        self.canvas = tk.Canvas(root, bg="#1e1e2f", highlightthickness=0)
        self.scroll_y = tk.Scrollbar(root, orient="vertical", command=self.canvas.yview)
        self.frame = tk.Frame(self.canvas, bg="#1e1e2f")

        self.canvas_frame = self.canvas.create_window((0, 0), window=self.frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scroll_y.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        self.frame.bind("<Configure>", self.on_frame_configure)
        self.canvas.bind("<Configure>", self.on_canvas_configure)

        self.logos_cache = {}

        # Menu déroulant pour sélectionner la compétition
        self.competition_var = tk.StringVar()
        self.competition_combobox = ttk.Combobox(root, textvariable=self.competition_var, font=("Helvetica", 12),
                                                 state="readonly")

        # Vérification que la liste de compétitions est bien peuplée
        competitions_list = list(COMPETITIONS.keys())
        if not competitions_list:
            print("Erreur : La liste des compétitions est vide.")
            self.competition_combobox['values'] = ["Aucune compétition disponible"]
        else:
            self.competition_combobox['values'] = competitions_list

        self.competition_combobox.pack(pady=10)

        # Ajout d'une valeur par défaut (pour éviter l'erreur "Aucune compétition sélectionnée")
        if self.competition_combobox['values']:
            self.competition_combobox.current(0)  # Sélectionne la première compétition par défaut

    def analyse_match(self, match):
        home = match['homeTeam']['name']
        away = match['awayTeam']['name']
        date = match['utcDate']
        status = match['status']
        confidence = 70
        prediction = f"{home} gagnera"
        home_id = match['homeTeam']['id']
        away_id = match['awayTeam']['id']

        # Ajoutez ceci pour vérifier les données du match
        print(f"Match analysé: {home} vs {away} - {date} - Statut: {status} - Prédiction: {prediction}")

        return {
            "home": home,
            "away": away,
            "home_id": home_id,
            "away_id": away_id,
            "date": date,
            "prediction": prediction,
            "confidence": confidence
        }

    def get_logos(self, home_id, away_id):
        def get_logo_image(team_id):
            if team_id in self.logos_cache:
                return self.logos_cache[team_id]

            logo_url = get_team_logo(team_id)

            if logo_url:
                retries = 3  # Nombre de tentatives
                for attempt in range(retries):
                    try:
                        response = requests.get(logo_url, timeout=10)  # Timeout de 10 secondes
                        response.raise_for_status()  # Vérifie si la réponse est valide (200 OK)
                        img_data = BytesIO(response.content)
                        img = Image.open(img_data).resize((40, 40))
                        photo = ImageTk.PhotoImage(img)
                        self.logos_cache[team_id] = photo
                        return photo
                    except requests.exceptions.RequestException as e:
                        if attempt < retries - 1:
                            sleep(2)  # Attendre 2 secondes avant de réessayer
                            continue
                        else:
                            print(f"Erreur lors de la récupération du logo pour l'équipe {team_id}: {e}")
                            break

            default = ImageTk.PhotoImage(Image.new('RGB', (40, 40), color='gray'))
            self.logos_cache[team_id] = default
            return default

        logos = {
            "home": get_logo_image(home_id),
            "away": get_logo_image(away_id)
        }

        return logos

    def on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_frame, width=event.width)

    def generer(self):
        selected_competition = self.competition_var.get()

        # Vérifier si une compétition a bien été sélectionnée
        if not selected_competition or selected_competition == "Aucune compétition disponible":
            print("Aucune compétition sélectionnée")
            return

        competition_code = COMPETITIONS.get(selected_competition)
        if not competition_code:
            print("Compétition invalide sélectionnée")
            return

        matches = get_matches(competition_code)

        if not matches:
            no_data_label = tk.Label(self.frame, text=f"Aucun match trouvé pour la compétition {selected_competition}.",
                                     font=("Helvetica", 12), fg="#ffffff", bg="#2e2e3f")
            no_data_label.pack(pady=10)

        for match in matches:
            analyse = self.analyse_match(match)
            self.afficher_match(analyse, selected_competition)

    def afficher_match(self, analyse, competition):
        container = tk.Frame(self.frame, bg="#2e2e3f", padx=10, pady=10)
        container.pack(padx=10, pady=10, fill=tk.X)

        logos = self.get_logos(analyse["home_id"], analyse["away_id"])

        logo_home = tk.Label(container, image=logos["home"], bg="#2e2e3f")
        logo_home.image = logos["home"]
        logo_home.pack(side=tk.LEFT, padx=5)

        match_label = tk.Label(container, text=f"{analyse['home']} vs {analyse['away']}",
                               font=("Helvetica", 14, "bold"), fg="#ffffff", bg="#2e2e3f")
        match_label.pack(side=tk.LEFT, padx=10)

        logo_away = tk.Label(container, image=logos["away"], bg="#2e2e3f")
        logo_away.image = logos["away"]
        logo_away.pack(side=tk.LEFT, padx=5)

        prediction_label = tk.Label(container, text=f"Prédiction : {analyse['prediction']} - Confiance : {analyse['confidence']}%",
                                    font=("Helvetica", 12), fg="#ffffff", bg="#2e2e3f")
        prediction_label.pack(pady=5)

# Créer la fenêtre principale
root = tk.Tk()
app = FootballApp(root)
root.mainloop()
