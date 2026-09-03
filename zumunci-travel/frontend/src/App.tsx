import { useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import {
  Link,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import {
  api,
  clearToken,
  formatXof,
  getToken,
  MODE_LABELS,
  setToken,
  VERIF_LABELS,
} from "./api";
import type { Booking, City, ProductConfig, Ride, SafetyCharter, User } from "./api";
import "./App.css";

function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    if (!getToken()) {
      setUser(null);
      setLoading(false);
      return;
    }
    try {
      setUser(await api.me());
    } catch {
      clearToken();
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const logout = () => {
    clearToken();
    setUser(null);
  };

  return { user, loading, refresh, logout };
}

function Shell({
  user,
  onLogout,
  children,
}: {
  user: User | null;
  onLogout: () => void;
  children: ReactNode;
}) {
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    // Ferme le menu mobile dès qu'on change de page.
    setMenuOpen(false);
  }, [location.pathname]);

  return (
    <div className="app-shell">
      <header className="topbar">
        <Link to="/" className="brand">
          <span className="brand-mark">Z</span>
          <div>
            <strong>ZumunciTravel</strong>
            <small>Voyagez en confiance</small>
          </div>
        </Link>
        <nav className={menuOpen ? "nav nav-open" : "nav"} aria-label="Navigation principale">
          <button
            type="button"
            className="menu-button"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((v) => !v)}
          >
            Menu
          </button>

          <div className="nav-links" id="primary-nav-links">
            <Link to="/" onClick={() => setMenuOpen(false)}>
              Rechercher
            </Link>
            <Link to="/publish" onClick={() => setMenuOpen(false)}>
              Publier
            </Link>
            <Link to="/safety" onClick={() => setMenuOpen(false)}>
              Sécurité
            </Link>
            {user ? (
              <>
                <Link to="/verify" onClick={() => setMenuOpen(false)}>
                  Vérification
                </Link>
                <Link to="/me" onClick={() => setMenuOpen(false)}>
                  Compte
                </Link>
                {user.role === "admin" && (
                  <Link to="/admin" onClick={() => setMenuOpen(false)}>
                    Admin
                  </Link>
                )}
                <button
                  type="button"
                  className="linkish"
                  onClick={() => {
                    setMenuOpen(false);
                    onLogout();
                  }}
                >
                  Sortir
                </button>
              </>
            ) : (
              <Link to="/login" className="btn btn-small" onClick={() => setMenuOpen(false)}>
                Connexion
              </Link>
            )}
          </div>
        </nav>
      </header>
      <main>{children}</main>
      <footer className="footer">
        <p>
          ZumunciTravel — mise en relation contrôlée · identité vérifiée · contact masqué jusqu’au
          paiement · XOF
        </p>
      </footer>
    </div>
  );
}

function HomePage() {
  const [cities, setCities] = useState<City[]>([]);
  const [config, setConfig] = useState<ProductConfig | null>(null);
  const [origin, setOrigin] = useState("Niamey");
  const [destination, setDestination] = useState("Maradi");
  const [date, setDate] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    void api.cities().then(setCities).catch(() => setCities([]));
    void api.productConfig().then(setConfig).catch(() => setConfig(null));
  }, []);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const params = new URLSearchParams();
    if (origin) params.set("origin", origin);
    if (destination) params.set("destination", destination);
    if (date) params.set("departure_date", date);
    navigate(`/search?${params}`);
  };

  return (
    <section className="hero">
      {config && (
        <div className="notice">
          <strong>Couverture nationale</strong> — {config.regions.length} régions :{" "}
          {config.regions.join(", ")}. Villes desservies : {config.service_cities.length}.
          Commission {(config.commission_rate * 100).toFixed(0)} % · KYC ≤ {config.kyc_sla_hours}h ·
          cash interdit en covoiturage.
        </div>
      )}
      <div className="hero-copy">
        <p className="eyebrow">Transport sécurisé · Niger</p>
        <h1>ZumunciTravel : voyagez sans arnaque ni relation déplacée.</h1>
        <p>
          Vérification d’identité avant toute mise en relation. Contact (appel/WhatsApp) débloqué
          uniquement après paiement Mobile Money. Transport uniquement — pas de rencontres.
        </p>
      </div>
      <form className="search-card" onSubmit={onSubmit}>
        <label>
          De
          <select value={origin} onChange={(e) => setOrigin(e.target.value)} required>
            <option value="">Ville de départ</option>
            {cities.map((c) => (
              <option key={c.id} value={c.name}>
                {c.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Vers
          <select value={destination} onChange={(e) => setDestination(e.target.value)} required>
            <option value="">Ville d&apos;arrivée</option>
            {cities.map((c) => (
              <option key={c.id} value={c.name}>
                {c.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Date
          <input type="date" value={date} onChange={(e) => setDate(e.target.value)} />
        </label>
        <button className="btn btn-primary" type="submit">
          Rechercher
        </button>
      </form>
      <div className="usp-grid">
        <article>
          <h3>Vérification KYC</h3>
          <p>CNI / passeport / permis validés avant publication ou réservation.</p>
        </article>
        <article>
          <h3>Contact protégé</h3>
          <p>Numéro masqué jusqu’au paiement Mobile Money confirmé.</p>
        </article>
        <article>
          <h3>Anti-arnaque</h3>
          <p>Paiement sur plateforme + signalement immédiat des abus.</p>
        </article>
      </div>
    </section>
  );
}

function RideCard({ ride }: { ride: Ride }) {
  return (
    <Link to={`/rides/${ride.id}`} className="ride-card">
      <div className="ride-top">
        <span className="badge">{MODE_LABELS[ride.mode]}</span>
        <strong>{formatXof(ride.price_per_seat)}</strong>
      </div>
      <h3>
        {ride.origin_city} → {ride.destination_city}
      </h3>
      <p>
        {ride.departure_date} · {ride.departure_time} · {ride.seats_available} place
        {ride.seats_available > 1 ? "s" : ""}
      </p>
      <p className="muted">
        {ride.driver.full_name}
        {ride.driver.is_verified ? " · ✓ vérifié" : ""}
        {" · "}
        {ride.driver.contact_hidden ? "contact masqué" : ride.driver.phone}
        {ride.women_priority ? " · priorité femmes" : ""}
        {ride.night_departure ? " · départ soir/nuit" : ""}
      </p>
    </Link>
  );
}

function SearchPage() {
  const [params, setParams] = useSearchParams();
  const [rides, setRides] = useState<Ride[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [mode, setMode] = useState(params.get("mode") || "");
  const [womenOnly, setWomenOnly] = useState(params.get("women_priority") === "true");
  const [region, setRegion] = useState(params.get("region") || "");

  useEffect(() => {
    setLoading(true);
    void api
      .rides(params)
      .then(setRides)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [params]);

  const applyFilters = (e: FormEvent) => {
    e.preventDefault();
    const next = new URLSearchParams(params);
    if (mode) next.set("mode", mode);
    else next.delete("mode");
    if (womenOnly) next.set("women_priority", "true");
    else next.delete("women_priority");
    if (region) next.set("region", region);
    else next.delete("region");
    setParams(next);
  };

  return (
    <section className="stack">
      <h2>Résultats</h2>
      <p className="muted">
        Seuls les convoyeurs <strong>vérifiés</strong> apparaissent. Contacts masqués avant paiement.
      </p>
      <form className="form filters" onSubmit={applyFilters}>
        <label>
          Mode
          <select value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="">Tous</option>
            <option value="carpool">Covoiturage</option>
            <option value="bush_taxi">Taxi brousse</option>
            <option value="bus">Bus</option>
          </select>
        </label>
        <label>
          Région
          <select value={region} onChange={(e) => setRegion(e.target.value)}>
            <option value="">Toutes</option>
            {["Agadez", "Diffa", "Dosso", "Maradi", "Tahoua", "Tillabéri", "Zinder", "Niamey"].map(
              (r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ),
            )}
          </select>
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={womenOnly}
            onChange={(e) => setWomenOnly(e.target.checked)}
          />
          Priorité femmes uniquement
        </label>
        <button className="btn btn-primary" type="submit">
          Filtrer
        </button>
      </form>
      {loading && <p>Chargement…</p>}
      {error && <p className="error">{error}</p>}
      {!loading && !error && rides.length === 0 && (
        <div className="empty">Aucun trajet trouvé. Publiez le vôtre après vérification.</div>
      )}
      <div className="ride-list">
        {rides.map((ride) => (
          <RideCard key={ride.id} ride={ride} />
        ))}
      </div>
    </section>
  );
}

function RideDetailPage({ user }: { user: User | null }) {
  const { id } = useParams();
  const navigate = useNavigate();
  const [ride, setRide] = useState<Ride | null>(null);
  const [seats, setSeats] = useState(1);
  const [provider, setProvider] = useState("orange_money");
  const [providers, setProviders] = useState<string[]>([]);
  const [config, setConfig] = useState<ProductConfig | null>(null);
  const [message, setMessage] = useState("");
  const [whatsappUrl, setWhatsappUrl] = useState<string | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!id) return;
    void api.ride(Number(id)).then(setRide).catch((e: Error) => setError(e.message));
    void api.providers().then(setProviders).catch(() => undefined);
    void api.productConfig().then(setConfig).catch(() => setConfig(null));
  }, [id]);

  const allowedProviders = useMemo(() => {
    const all = providers.length ? providers : ["orange_money", "airtel_money", "moov_money", "cash"];
    if (!ride || !config) return all;
    if (config.cash_allowed_modes.includes(ride.mode)) return all;
    return all.filter((p) => p !== "cash");
  }, [providers, ride, config]);

  useEffect(() => {
    if (allowedProviders.length && !allowedProviders.includes(provider)) {
      setProvider(allowedProviders[0]);
    }
  }, [allowedProviders, provider]);

  const book = async () => {
    if (!user) {
      navigate("/login");
      return;
    }
    if (user.verification_status !== "verified") {
      navigate("/verify");
      return;
    }
    if (!ride) return;
    setError("");
    try {
      const booking = await api.book(ride.id, {
        seats,
        payment_provider: provider,
        payment_phone: user.phone,
      });
      if (booking.payment) {
        await api.confirmPayment(booking.payment.id, true);
      }
      const contact = await api.revealContact(booking.id);
      setWhatsappUrl(contact.driver_whatsapp_url);
      setMessage(
        `Réservation confirmée (${formatXof(booking.total_amount)}, dont commission ${formatXof(booking.platform_fee)}). ` +
          `Contact : ${contact.driver_phone}. ${contact.warning}`,
      );
      setRide(await api.ride(ride.id));
    } catch (e) {
      setError((e as Error).message);
    }
  };

  if (error && !ride) return <p className="error">{error}</p>;
  if (!ride) return <p>Chargement…</p>;

  return (
    <section className="stack detail">
      <span className="badge">{MODE_LABELS[ride.mode]}</span>
      <h2>
        {ride.origin_city} → {ride.destination_city}
      </h2>
      <p>
        {ride.departure_date} à {ride.departure_time}
      </p>
      <p className="price">{formatXof(ride.price_per_seat)} / place</p>
      <ul className="facts">
        <li>
          <strong>Places :</strong> {ride.seats_available}/{ride.seats_total}
        </li>
        <li>
          <strong>Convoyeur :</strong> {ride.driver.full_name}{" "}
          {ride.driver.is_verified ? "(✓ vérifié)" : ""}
        </li>
        <li>
          <strong>Téléphone :</strong>{" "}
          {ride.driver.contact_hidden
            ? `${ride.driver.phone} — masqué jusqu’au paiement`
            : ride.driver.phone}
        </li>
        {ride.women_priority && (
          <li>
            <strong>Option :</strong> priorité femmes (ambiance professionnelle)
          </li>
        )}
        {ride.night_departure && (
          <li>
            <strong>Attention :</strong> départ soir/nuit — restez prudente·e
          </li>
        )}
        {ride.vehicle_info && (
          <li>
            <strong>Véhicule :</strong> {ride.vehicle_info}
          </li>
        )}
        {ride.meeting_point && (
          <li>
            <strong>RDV :</strong> {ride.meeting_point}
          </li>
        )}
      </ul>
      <div className="notice">
        Contact (appel/WhatsApp) débloqué après paiement Mobile Money. En covoiturage, le cash est
        interdit. Commission plateforme {(config ? config.commission_rate * 100 : 10).toFixed(0)} %.
      </div>
      <div className="book-box">
        <label>
          Places
          <input
            type="number"
            min={1}
            max={ride.seats_available}
            value={seats}
            onChange={(e) => setSeats(Number(e.target.value))}
          />
        </label>
        <label>
          Paiement
          <select value={provider} onChange={(e) => setProvider(e.target.value)}>
            {allowedProviders.map((p) => (
              <option key={p} value={p}>
                {p.replaceAll("_", " ")}
              </option>
            ))}
          </select>
        </label>
        <button className="btn btn-primary" type="button" onClick={() => void book()}>
          Réserver · {formatXof(seats * ride.price_per_seat)}
        </button>
      </div>
      {message && <p className="success">{message}</p>}
      {whatsappUrl && (
        <a className="btn btn-primary" href={whatsappUrl} target="_blank" rel="noreferrer">
          Contacter le convoyeur sur WhatsApp
        </a>
      )}
      {error && <p className="error">{error}</p>}
    </section>
  );
}

function AuthPage({
  mode,
  onAuth,
}: {
  mode: "login" | "register";
  onAuth: () => Promise<void>;
}) {
  const navigate = useNavigate();
  const [phone, setPhone] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [city, setCity] = useState("Niamey");
  const [acceptCharter, setAcceptCharter] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      if (mode === "register" && !acceptCharter) {
        throw new Error("Vous devez accepter la charte de sécurité");
      }
      const data =
        mode === "login"
          ? await api.login({ phone, password })
          : await api.register({
              phone,
              password,
              full_name: fullName,
              city,
              role: "both",
              accept_safety_charter: acceptCharter,
            });
      setToken(data.access_token);
      await onAuth();
      navigate(mode === "register" ? "/verify" : "/me");
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <section className="stack narrow">
      <h2>{mode === "login" ? "Connexion" : "Créer un compte"}</h2>
      <p className="muted">Numéro nigérien (+227…). La vérification est obligatoire avant réservation.</p>
      <form className="form" onSubmit={(e) => void submit(e)}>
        {mode === "register" && (
          <>
            <label>
              Nom complet
              <input value={fullName} onChange={(e) => setFullName(e.target.value)} required />
            </label>
            <label>
              Ville
              <input value={city} onChange={(e) => setCity(e.target.value)} />
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={acceptCharter}
                onChange={(e) => setAcceptCharter(e.target.checked)}
              />
              J’accepte la charte de sécurité (transport uniquement, anti-arnaque)
            </label>
          </>
        )}
        <label>
          Téléphone
          <input
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            placeholder="90 00 00 02"
            required
          />
        </label>
        <label>
          Mot de passe
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={6}
          />
        </label>
        <button className="btn btn-primary" type="submit">
          {mode === "login" ? "Se connecter" : "S'inscrire"}
        </button>
      </form>
      {error && <p className="error">{error}</p>}
      <p className="muted">
        Démo vérifiée : <code>90000002</code> / <code>zumunci123</code>
      </p>
      {mode === "login" ? (
        <Link to="/register">Pas encore de compte ? Inscrivez-vous</Link>
      ) : (
        <Link to="/login">Déjà inscrit ? Connectez-vous</Link>
      )}
    </section>
  );
}

function VerifyPage({ user, onRefresh }: { user: User | null; onRefresh: () => Promise<void> }) {
  const [docType, setDocType] = useState("national_id");
  const [docNumber, setDocNumber] = useState("");
  const [idName, setIdName] = useState(user?.full_name || "");
  const [accept, setAccept] = useState(true);
  const [otpCode, setOtpCode] = useState("");
  const [demoOtp, setDemoOtp] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");

  if (!user) return <Navigate to="/login" replace />;

  const sendOtp = async () => {
    setError("");
    try {
      const res = await api.sendOtp();
      setDemoOtp(res.demo_code);
      setOk(res.message);
      await onRefresh();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const confirmOtp = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await api.verifyOtp(otpCode);
      setOk("Numéro vérifié avec succès.");
      await onRefresh();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await api.submitVerification({
        id_document_type: docType,
        id_document_number: docNumber,
        id_full_name: idName,
        accept_safety_charter: accept,
      });
      setOk("Dossier envoyé. Un agent ZumunciTravel validera votre identité avant mise en relation.");
      await onRefresh();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <section className="stack narrow">
      <h2>Vérification</h2>
      <p className="muted">
        Téléphone : <strong>{user.phone_verified ? "vérifié" : "non vérifié"}</strong> · Identité :{" "}
        <strong>{VERIF_LABELS[user.verification_status]}</strong>
      </p>

      {!user.phone_verified && (
        <div className="form">
          <h3>1. Vérifier le téléphone (OTP)</h3>
          <button className="btn btn-primary" type="button" onClick={() => void sendOtp()}>
            Envoyer le code SMS (simulé)
          </button>
          {demoOtp && <p className="notice">Code démo : <code>{demoOtp}</code></p>}
          <form onSubmit={(e) => void confirmOtp(e)}>
            <label>
              Code OTP
              <input value={otpCode} onChange={(e) => setOtpCode(e.target.value)} required />
            </label>
            <button className="btn btn-primary" type="submit">
              Valider le numéro
            </button>
          </form>
        </div>
      )}

      {user.verification_status === "verified" ? (
        <div className="success">
          Votre identité est vérifiée. Vous pouvez publier et réserver en toute sécurité.
        </div>
      ) : (
        <form className="form" onSubmit={(e) => void submit(e)}>
          <h3>2. Pièce d’identité</h3>
          <label>
            Type de pièce
            <select value={docType} onChange={(e) => setDocType(e.target.value)}>
              <option value="national_id">CNI / Carte d’identité</option>
              <option value="passport">Passeport</option>
              <option value="drivers_license">Permis de conduire</option>
            </select>
          </label>
          <label>
            Numéro de pièce
            <input value={docNumber} onChange={(e) => setDocNumber(e.target.value)} required />
          </label>
          <label>
            Nom sur la pièce
            <input value={idName} onChange={(e) => setIdName(e.target.value)} required />
          </label>
          <label className="check">
            <input type="checkbox" checked={accept} onChange={(e) => setAccept(e.target.checked)} />
            J’accepte la charte : transport uniquement, pas de relations déplacées, pas de paiement
            hors plateforme
          </label>
          <button className="btn btn-primary" type="submit">
            Soumettre pour vérification
          </button>
        </form>
      )}
      {ok && <p className="success">{ok}</p>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}

function SafetyPage() {
  const [charter, setCharter] = useState<SafetyCharter | null>(null);
  useEffect(() => {
    void api.charter().then(setCharter);
  }, []);
  return (
    <section className="stack">
      <h2>{charter?.title || "Sécurité ZumunciTravel"}</h2>
      <p className="muted">Version {charter?.version}</p>
      <ol className="rules">
        {(charter?.rules || []).map((rule) => (
          <li key={rule}>{rule}</li>
        ))}
      </ol>
      <div className="notice">
        En cas d’arnaque, harcèlement ou proposition déplacée : utilisez le signalement depuis votre
        compte après une réservation, ou contactez le support.
      </div>
    </section>
  );
}

function PublishPage({ user }: { user: User | null }) {
  const navigate = useNavigate();
  const [cities, setCities] = useState<City[]>([]);
  const [form, setForm] = useState({
    origin_city: "Niamey",
    destination_city: "Maradi",
    departure_date: "",
    departure_time: "07:00",
    seats_total: 3,
    price_per_seat: 5000,
    mode: "carpool",
    vehicle_info: "",
    meeting_point: "",
    notes: "",
    women_priority: false,
  });
  const [error, setError] = useState("");

  useEffect(() => {
    void api.cities().then(setCities);
  }, []);

  if (!user) return <Navigate to="/login" replace />;
  if (user.verification_status !== "verified") return <Navigate to="/verify" replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      const ride = await api.publishRide(form);
      navigate(`/rides/${ride.id}`);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <section className="stack narrow">
      <h2>Publier un trajet</h2>
      <p className="muted">
        Toutes les régions du Niger sont ouvertes. Numéro masqué jusqu’au paiement.
      </p>
      <form className="form" onSubmit={(e) => void submit(e)}>
        <label>
          De
          <select
            value={form.origin_city}
            onChange={(e) => setForm({ ...form, origin_city: e.target.value })}
          >
            {cities.map((c) => (
              <option key={c.id}>{c.name}</option>
            ))}
          </select>
        </label>
        <label>
          Vers
          <select
            value={form.destination_city}
            onChange={(e) => setForm({ ...form, destination_city: e.target.value })}
          >
            {cities.map((c) => (
              <option key={c.id}>{c.name}</option>
            ))}
          </select>
        </label>
        <label>
          Date
          <input
            type="date"
            required
            value={form.departure_date}
            onChange={(e) => setForm({ ...form, departure_date: e.target.value })}
          />
        </label>
        <label>
          Heure
          <input
            type="time"
            required
            value={form.departure_time}
            onChange={(e) => setForm({ ...form, departure_time: e.target.value })}
          />
        </label>
        <label>
          Places
          <input
            type="number"
            min={1}
            max={50}
            value={form.seats_total}
            onChange={(e) => setForm({ ...form, seats_total: Number(e.target.value) })}
          />
        </label>
        <label>
          Prix / place (F CFA)
          <input
            type="number"
            min={500}
            value={form.price_per_seat}
            onChange={(e) => setForm({ ...form, price_per_seat: Number(e.target.value) })}
          />
        </label>
        <label>
          Mode
          <select value={form.mode} onChange={(e) => setForm({ ...form, mode: e.target.value })}>
            <option value="carpool">Covoiturage</option>
            <option value="bush_taxi">Taxi brousse</option>
            <option value="bus">Bus</option>
          </select>
        </label>
        <label>
          Point de rendez-vous
          <input
            value={form.meeting_point}
            onChange={(e) => setForm({ ...form, meeting_point: e.target.value })}
          />
        </label>
        <label>
          Véhicule
          <input
            value={form.vehicle_info}
            onChange={(e) => setForm({ ...form, vehicle_info: e.target.value })}
          />
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={form.women_priority}
            onChange={(e) => setForm({ ...form, women_priority: e.target.checked })}
          />
          Trajet priorité femmes (ambiance professionnelle uniquement)
        </label>
        <button className="btn btn-primary" type="submit">
          Publier
        </button>
      </form>
      {error && <p className="error">{error}</p>}
    </section>
  );
}

function AccountPage({
  user,
  onRefresh,
}: {
  user: User | null;
  onRefresh: () => Promise<void>;
}) {
  const [bookings, setBookings] = useState<Booking[]>([]);
  const [rides, setRides] = useState<Ride[]>([]);
  const [reportMsg, setReportMsg] = useState("");
  const [emName, setEmName] = useState(user?.emergency_contact_name || "");
  const [emPhone, setEmPhone] = useState(user?.emergency_contact_phone || "");

  const reload = async () => {
    setBookings(await api.myBookings());
    setRides(await api.myRides());
  };

  useEffect(() => {
    if (!user) return;
    void reload().catch(() => undefined);
    setEmName(user.emergency_contact_name || "");
    setEmPhone(user.emergency_contact_phone || "");
  }, [user]);

  if (!user) return <Navigate to="/login" replace />;

  const reportDriver = async (booking: Booking) => {
    if (!booking.ride) return;
    try {
      await api.report({
        reported_user_id: booking.ride.driver.id,
        booking_id: booking.id,
        reason: "inappropriate_behavior",
        details:
          "Signalement depuis le compte : comportement inapproprié ou tentative hors plateforme.",
      });
      setReportMsg("Signalement envoyé à ZumunciTravel. Merci de protéger la communauté.");
    } catch (e) {
      setReportMsg((e as Error).message);
    }
  };

  const cancel = async (booking: Booking) => {
    try {
      await api.cancelBooking(booking.id, "Annulation depuis mon compte");
      setReportMsg("Réservation annulée.");
      await reload();
    } catch (e) {
      setReportMsg((e as Error).message);
    }
  };

  const share = async (booking: Booking) => {
    try {
      const res = await api.shareTrip(booking.id);
      if (res.emergency_whatsapp_url) {
        window.open(res.emergency_whatsapp_url, "_blank");
      } else {
        await navigator.clipboard.writeText(res.share_text);
        setReportMsg("Texte de partage copié. Ajoutez un contact d’urgence pour WhatsApp direct.");
      }
    } catch (e) {
      setReportMsg((e as Error).message);
    }
  };

  const saveEmergency = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await api.setEmergencyContact(emName, emPhone);
      setReportMsg("Contact d’urgence enregistré.");
      await onRefresh();
    } catch (err) {
      setReportMsg((err as Error).message);
    }
  };

  return (
    <section className="stack">
      <h2>Bonjour, {user.full_name}</h2>
      <p className="muted">
        {user.phone} · {user.phone_verified ? "OTP OK" : "OTP manquant"} ·{" "}
        {VERIF_LABELS[user.verification_status]}
        {user.accepted_safety_charter ? " · charte acceptée" : ""}
      </p>
      {(user.verification_status !== "verified" || !user.phone_verified) && (
        <div className="notice">
          Complétez <Link to="/verify">OTP + identité</Link> pour réserver ou publier.
        </div>
      )}

      <form className="form narrow" onSubmit={(e) => void saveEmergency(e)}>
        <h3>Contact d’urgence</h3>
        <label>
          Nom
          <input value={emName} onChange={(e) => setEmName(e.target.value)} required />
        </label>
        <label>
          Téléphone
          <input value={emPhone} onChange={(e) => setEmPhone(e.target.value)} required />
        </label>
        <button className="btn btn-primary" type="submit">
          Enregistrer
        </button>
      </form>

      <h3>Mes réservations</h3>
      <div className="ride-list">
        {bookings.length === 0 && <div className="empty">Aucune réservation pour l’instant.</div>}
        {bookings.map((b) => (
          <article key={b.id} className="ride-card static">
            <div className="ride-top">
              <span className="badge">{b.status}</span>
              <strong>{formatXof(b.total_amount)}</strong>
            </div>
            <h3>
              {b.ride
                ? `${b.ride.origin_city} → ${b.ride.destination_city}`
                : `Trajet #${b.ride_id}`}
            </h3>
            <p>
              Contact {b.contact_unlocked ? "débloqué" : "masqué"}
              {b.driver_phone ? ` · ${b.driver_phone}` : ""}
              {" · "}
              commission {formatXof(b.platform_fee || 0)}
            </p>
            <div className="row-actions">
              {b.driver_whatsapp_url && (
                <a className="btn btn-small" href={b.driver_whatsapp_url} target="_blank" rel="noreferrer">
                  WhatsApp
                </a>
              )}
              {b.status !== "cancelled" && b.status !== "completed" && (
                <button type="button" className="btn btn-small" onClick={() => void cancel(b)}>
                  Annuler
                </button>
              )}
              {(b.status === "paid" || b.status === "completed") && (
                <button type="button" className="btn btn-small" onClick={() => void share(b)}>
                  Partager / urgence
                </button>
              )}
              <button type="button" className="btn btn-small danger" onClick={() => void reportDriver(b)}>
                Signaler
              </button>
            </div>
          </article>
        ))}
      </div>
      {reportMsg && <p className="success">{reportMsg}</p>}
      <h3>Mes trajets publiés</h3>
      <div className="ride-list">
        {rides.length === 0 && <div className="empty">Aucun trajet publié.</div>}
        {rides.map((ride) => (
          <RideCard key={ride.id} ride={ride} />
        ))}
      </div>
    </section>
  );
}

function AdminPage({ user }: { user: User | null }) {
  const [pending, setPending] = useState<User[]>([]);
  const [reports, setReports] = useState<import("./api").SafetyReport[]>([]);
  const [msg, setMsg] = useState("");

  const load = async () => {
    setPending(await api.pendingVerifications());
    setReports(await api.adminReports());
  };

  useEffect(() => {
    if (user?.role === "admin") void load().catch(() => undefined);
  }, [user]);

  if (!user) return <Navigate to="/login" replace />;
  if (user.role !== "admin") return <Navigate to="/" replace />;

  const review = async (id: number, approve: boolean) => {
    await api.reviewVerification(id, approve, approve ? "Validé" : "Rejeté");
    setMsg(approve ? "Identité validée" : "Dossier rejeté");
    await load();
  };

  return (
    <section className="stack">
      <h2>Admin — vérifications en attente</h2>
      {msg && <p className="success">{msg}</p>}
      <div className="ride-list">
        {pending.length === 0 && <div className="empty">Aucune demande en attente.</div>}
        {pending.map((u) => (
          <article key={u.id} className="ride-card static">
            <h3>
              {u.full_name} · {u.phone}
            </h3>
            <p className="muted">{VERIF_LABELS[u.verification_status]}</p>
            <div className="row-actions">
              <button type="button" className="btn btn-small" onClick={() => void review(u.id, true)}>
                Approuver
              </button>
              <button
                type="button"
                className="btn btn-small danger"
                onClick={() => void review(u.id, false)}
              >
                Rejeter
              </button>
            </div>
          </article>
        ))}
      </div>

      <h2>Signalements</h2>
      <div className="ride-list">
        {reports.length === 0 && <div className="empty">Aucun signalement.</div>}
        {reports.map((r) => (
          <article key={r.id} className="ride-card static">
            <div className="ride-top">
              <span className="badge">{r.status}</span>
              <strong>{r.reason}</strong>
            </div>
            <p>
              User #{r.reported_user_id} · {r.details}
            </p>
            <div className="row-actions">
              <button
                type="button"
                className="btn btn-small"
                onClick={() => void api.reviewReport(r.id, "resolved").then(load)}
              >
                Résoudre
              </button>
              <button
                type="button"
                className="btn btn-small danger"
                onClick={() =>
                  void api.reviewReport(r.id, "resolved", true).then(() => {
                    setMsg("Utilisateur suspendu");
                    return load();
                  })
                }
              >
                Suspendre
              </button>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

export default function App() {
  const auth = useAuth();
  const ready = useMemo(() => !auth.loading, [auth.loading]);

  if (!ready) {
    return <div className="boot">Chargement ZumunciTravel…</div>;
  }

  return (
    <Shell user={auth.user} onLogout={auth.logout}>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/search" element={<SearchPage />} />
        <Route path="/rides/:id" element={<RideDetailPage user={auth.user} />} />
        <Route path="/publish" element={<PublishPage user={auth.user} />} />
        <Route
          path="/me"
          element={<AccountPage user={auth.user} onRefresh={auth.refresh} />}
        />
        <Route path="/verify" element={<VerifyPage user={auth.user} onRefresh={auth.refresh} />} />
        <Route path="/safety" element={<SafetyPage />} />
        <Route path="/admin" element={<AdminPage user={auth.user} />} />
        <Route path="/login" element={<AuthPage mode="login" onAuth={auth.refresh} />} />
        <Route path="/register" element={<AuthPage mode="register" onAuth={auth.refresh} />} />
      </Routes>
    </Shell>
  );
}