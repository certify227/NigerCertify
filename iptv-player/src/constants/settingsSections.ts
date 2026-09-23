export interface SettingsSection {
  id: string
  title: string
  items: readonly string[]
}

export const UPCOMING_SETTINGS: readonly SettingsSection[] = [
  {
    id: 'general',
    title: 'Général',
    items: ['Langue', 'Démarrage automatique', 'Lecture automatique de la dernière chaîne'],
  },
  {
    id: 'player',
    title: 'Lecteur',
    items: ['Lecture automatique', 'Qualité préférée', 'Mémoire tampon', 'Reconnexion automatique'],
  },
  {
    id: 'network',
    title: 'Réseau',
    items: ["Délai d'attente", 'Nombre de tentatives', 'Délai entre les tentatives'],
  },
  {
    id: 'epg',
    title: 'Guide TV',
    items: ['URL XMLTV', 'Fréquence de synchronisation'],
  },
  {
    id: 'storage',
    title: 'Stockage',
    items: ["Vider l'historique", 'Effacer le cache', "Réinitialiser l'application"],
  },
]
