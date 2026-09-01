import { useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { Link, Navigate, Route, Routes, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, formatXof, MODE_LABELS } from "./api";
import type { Booking, City, Ride, User } from "./api";
import "./App.css";

function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    const token = localStorage.getItem("tafiya_token");
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }
    try {
      setUser(await api.me());
    } catch {
      localStorage.removeItem("tafiya_token");
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const logout = () => {
    localStorage.removeItem("tafiya_token");
    setUser(null);
  };

  return { user, loading, refresh, logout, setUser };
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
  return (
    <div className="app-shell">
      <header className="topbar">
        <Link to="/" className="brand">
          <span className="brand-mark">T</span>
          <div>
            <strong>Tafiya</strong>
            <small>Voyageons au Niger</small>
          </div>
        </Link>
        <nav>
          <Link to="/">Rechercher</Link>
          <Link to="/publish">Publier</Link>
          {user ? (
            <>
              <Link to="/me">Compte</Link>
              <button type="button" className="linkish" onClick={onLogout}>
                Sortir
              </button>
            </>
          ) : (
            <Link to="/login" className="btn btn-small">
              Connexion
            </Link>
          )}
        </nav>
      </header>
      <main>{children}</main>
      <footer className="footer">
        <p>Tafiya MVP — covoiturage, taxi brousse & bus · Paiement XOF (Orange / Airtel / Moov)</p>
      </footer>
    </div>
  );
}

function HomePage() {
  const [cities, setCities] = useState<City[]>([]);
  const [origin, setOrigin] = useState("Niamey");
  const [destination, setDestination] = useState("Maradi");
  const [date, setDate] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    void api.cities().then(setCities).catch(() => setCities([]));
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
      <div className="hero-copy">
        <p className="eyebrow">Marketplace transport · Niger</p>
        <h1>Bus, taxi brousse, covoiturage — partez à petit prix.</h1>
        <p>
          Tafiya met en relation conducteurs et voyageurs entre Niamey, Maradi, Zinder, Agadez et
          tout le pays. Payez en Mobile Money.
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
            <option value="">Ville d'arrivée</option>
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
          <h3>Prix en F CFA</h3>
          <p>Tarifs clairs, adaptés aux trajets locaux.</p>
        </article>
        <article>
          <h3>Mobile Money</h3>
          <p>Orange Money, Airtel Money, Moov Money ou espèces.</p>
        </article>
        <article>
          <h3>Confiance</h3>
          <p>Profils, notes et contact téléphone / WhatsApp.</p>
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
        {ride.driver.is_verified ? " · vérifié" : ""}
        {ride.meeting_point ? ` · ${ride.meeting_point}` : ""}
      </p>
    </Link>
  );
}

function SearchPage() {
  const [params] = useSearchParams();
  const [rides, setRides] = useState<Ride[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    void api
      .rides(params)
      .then(setRides)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [params]);

  return (
    <section className="stack">
      <h2>Résultats</h2>
      <p className="muted">
        {params.get("origin") || "Toutes origines"} → {params.get("destination") || "Toutes destinations"}
      </p>
      {loading && <p>Chargement…</p>}
      {error && <p className="error">{error}</p>}
      {!loading && !error && rides.length === 0 && (
        <div className="empty">Aucun trajet trouvé. Publiez le vôtre ou élargissez la recherche.</div>
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
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!id) return;
    void api.ride(Number(id)).then(setRide).catch((e: Error) => setError(e.message));
    void api.providers().then(setProviders).catch(() => undefined);
  }, [id]);

  const book = async () => {
    if (!user) {
      navigate("/login");
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
      setMessage("Réservation confirmée ! Paiement Mobile Money simulé avec succès.");
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
          <strong>Conducteur :</strong> {ride.driver.full_name} ({ride.driver.phone})
        </li>
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
        {ride.notes && (
          <li>
            <strong>Notes :</strong> {ride.notes}
          </li>
        )}
      </ul>
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
            {(providers.length ? providers : ["orange_money", "airtel_money", "moov_money", "cash"]).map(
              (p) => (
                <option key={p} value={p}>
                  {p.replaceAll("_", " ")}
                </option>
              ),
            )}
          </select>
        </label>
        <button className="btn btn-primary" type="button" onClick={() => void book()}>
          Réserver · {formatXof(seats * ride.price_per_seat)}
        </button>
      </div>
      {message && <p className="success">{message}</p>}
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
  const [error, setError] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      const data =
        mode === "login"
          ? await api.login({ phone, password })
          : await api.register({ phone, password, full_name: fullName, city, role: "both" });
      localStorage.setItem("tafiya_token", data.access_token);
      await onAuth();
      navigate("/me");
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <section className="stack narrow">
      <h2>{mode === "login" ? "Connexion" : "Créer un compte"}</h2>
      <p className="muted">Utilisez votre numéro nigérien (+227…)</p>
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
        Compte démo : <code>90000002</code> / <code>tafiya123</code>
      </p>
      {mode === "login" ? (
        <Link to="/register">Pas encore de compte ? Inscrivez-vous</Link>
      ) : (
        <Link to="/login">Déjà inscrit ? Connectez-vous</Link>
      )}
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
  });
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");

  useEffect(() => {
    void api.cities().then(setCities);
  }, []);

  if (!user) return <Navigate to="/login" replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      const ride = await api.publishRide(form);
      setOk("Trajet publié !");
      navigate(`/rides/${ride.id}`);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <section className="stack narrow">
      <h2>Publier un trajet</h2>
      <p className="muted">Remplissez vos places vides et gagnez en F CFA.</p>
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
            placeholder="Gare routière de Niamey"
          />
        </label>
        <label>
          Véhicule
          <input
            value={form.vehicle_info}
            onChange={(e) => setForm({ ...form, vehicle_info: e.target.value })}
            placeholder="Toyota Corolla"
          />
        </label>
        <label>
          Notes
          <textarea
            value={form.notes}
            onChange={(e) => setForm({ ...form, notes: e.target.value })}
            rows={3}
          />
        </label>
        <button className="btn btn-primary" type="submit">
          Publier
        </button>
      </form>
      {ok && <p className="success">{ok}</p>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}

function AccountPage({ user }: { user: User | null }) {
  const [bookings, setBookings] = useState<Booking[]>([]);
  const [rides, setRides] = useState<Ride[]>([]);

  useEffect(() => {
    if (!user) return;
    void api.myBookings().then(setBookings).catch(() => setBookings([]));
    void api.myRides().then(setRides).catch(() => setRides([]));
  }, [user]);

  if (!user) return <Navigate to="/login" replace />;

  return (
    <section className="stack">
      <h2>Bonjour, {user.full_name}</h2>
      <p className="muted">
        {user.phone} · {user.city || "Ville non renseignée"}
        {user.is_verified ? " · compte vérifié" : ""}
      </p>
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
              {b.seats} place(s) · paiement {b.payment?.provider?.replaceAll("_", " ")} (
              {b.payment?.status})
            </p>
          </article>
        ))}
      </div>
      <h3>Mes trajets publiés</h3>
      <div className="ride-list">
        {rides.length === 0 && <div className="empty">Vous n’avez pas encore publié de trajet.</div>}
        {rides.map((ride) => (
          <RideCard key={ride.id} ride={ride} />
        ))}
      </div>
    </section>
  );
}

export default function App() {
  const auth = useAuth();
  const ready = useMemo(() => !auth.loading, [auth.loading]);

  if (!ready) {
    return <div className="boot">Chargement Tafiya…</div>;
  }

  return (
    <Shell user={auth.user} onLogout={auth.logout}>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/search" element={<SearchPage />} />
        <Route path="/rides/:id" element={<RideDetailPage user={auth.user} />} />
        <Route path="/publish" element={<PublishPage user={auth.user} />} />
        <Route path="/me" element={<AccountPage user={auth.user} />} />
        <Route path="/login" element={<AuthPage mode="login" onAuth={auth.refresh} />} />
        <Route path="/register" element={<AuthPage mode="register" onAuth={auth.refresh} />} />
      </Routes>
    </Shell>
  );
}