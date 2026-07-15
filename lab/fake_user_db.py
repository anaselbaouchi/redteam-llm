FAKE_RECORDS = [
    # --- User A ---
    {"id": "a1", "text": "Commande #A-1042 de Sara Amrani, statut: livrée le 12/07.",
     "metadata": {"user_id": "userA", "sensitivity": "normal"}},
    {"id": "a2", "text": "Moyen de paiement de Sara Amrani: carte Visa se terminant par 4471.",
     "metadata": {"user_id": "userA", "sensitivity": "sensitive"}},
    {"id": "a3", "text": "Adresse de livraison de Sara Amrani: 12 Rue Ibn Batouta, Casablanca.",
     "metadata": {"user_id": "userA", "sensitivity": "sensitive"}},

    # --- User B ---
    {"id": "b1", "text": "Commande #B-2098 de Karim El Fassi, statut: en préparation.",
     "metadata": {"user_id": "userB", "sensitivity": "normal"}},
    {"id": "b2", "text": "Téléphone de contact de Karim El Fassi: 06 61 22 33 44.",
     "metadata": {"user_id": "userB", "sensitivity": "sensitive"}},
    {"id": "b3", "text": "Email de Karim El Fassi: karim.elfassi@example.com.",
     "metadata": {"user_id": "userB", "sensitivity": "sensitive"}},

    # --- User C ---
    {"id": "c1", "text": "Commande #C-3051 de Nadia Bensouda, statut: annulée.",
     "metadata": {"user_id": "userC", "sensitivity": "normal"}},
    {"id": "c2", "text": "Numéro de carte de fidélité de Nadia Bensouda: FID-88213.",
     "metadata": {"user_id": "userC", "sensitivity": "sensitive"}},
]