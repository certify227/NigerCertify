/** Libellés UI FR / HA / ZAR (zarma) — périmètre élargi v1.2 */

export type AppLocale = "fr" | "ha" | "dje";

type Dict = Record<string, string>;

const FR: Dict = {
  nav_search: "Rechercher",
  nav_publish: "Publier",
  nav_companies: "Compagnies",
  nav_agents: "Agents",
  nav_ussd: "USSD",
  nav_safety: "Sécurité",
  nav_verify: "Vérification",
  nav_account: "Compte",
  nav_admin: "Admin",
  nav_login: "Connexion",
  nav_logout: "Sortir",
  search_results: "Résultats",
  search_filter: "Filtrer",
  search_mode: "Mode",
  search_region: "Région",
  search_max_price: "Prix max / place",
  search_women: "Priorité femmes uniquement",
  account_hello: "Bonjour",
  account_alerts: "Alertes trajets",
  account_earnings: "Gains conducteur",
  account_bookings: "Mes réservations",
  uemoa_live: "Corridors UEMOA live",
  sandbox_pay: "Paiement sandbox",
};

const HA: Dict = {
  ...FR,
  nav_search: "Nemo",
  nav_publish: "Wallafa",
  nav_companies: "Kamfanoni",
  nav_agents: "Wakilai",
  nav_safety: "Tsaro",
  nav_verify: "Tabbatarwa",
  nav_account: "Asusu",
  nav_admin: "Admin",
  nav_login: "Shiga",
  nav_logout: "Fita",
  search_results: "Sakamako",
  search_filter: "Tace",
  search_mode: "Yanayi",
  search_region: "Yankin",
  search_max_price: "Mafi tsada",
  search_women: "Mata kawai",
  account_hello: "Sannu",
  account_alerts: "Faɗakarwa",
  account_earnings: "Riba",
  account_bookings: "Ajiye na",
  uemoa_live: "Hanyoyin UEMOA",
  sandbox_pay: "Biya gwaji",
};

const DJE: Dict = {
  ...FR,
  nav_search: "Ceeci",
  nav_publish: "Wallafi",
  nav_companies: "Kampaniyan",
  nav_agents: "Wakilan",
  nav_safety: "Saajaw",
  nav_verify: "Tabatandi",
  nav_account: "Konto",
  nav_admin: "Admin",
  nav_login: "Huru",
  nav_logout: "Fatura",
  search_results: "Duuley",
  search_filter: "Siiyan",
  search_mode: "Alhiili",
  search_region: "Laabu",
  search_max_price: "Hayri beeri",
  search_women: "Woyey hinne",
  account_hello: "Fofo",
  account_alerts: "Bangayan",
  account_earnings: "Alfaa",
  account_bookings: "Nyaŋey",
  uemoa_live: "Fondiyan UEMOA",
  sandbox_pay: "Bannda gwaji",
};

const TABLES: Record<AppLocale, Dict> = { fr: FR, ha: HA, dje: DJE };

export function t(locale: AppLocale, key: string): string {
  return TABLES[locale][key] || TABLES.fr[key] || key;
}

export const LOCALE_STORAGE_KEY = "zumunci_locale";
