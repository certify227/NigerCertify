const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000/api";

export type User = {
  id: number;
  phone: string;
  full_name: string;
  role: string;
  city: string | null;
  is_verified: boolean;
};

export type City = {
  id: number;
  name: string;
  region: string;
};

export type Ride = {
  id: number;
  origin_city: string;
  destination_city: string;
  departure_date: string;
  departure_time: string;
  seats_total: number;
  seats_available: number;
  price_per_seat: number;
  currency: string;
  mode: "carpool" | "bush_taxi" | "bus";
  vehicle_info: string | null;
  meeting_point: string | null;
  notes: string | null;
  is_active: boolean;
  driver: {
    id: number;
    full_name: string;
    phone: string;
    is_verified: boolean;
    city: string | null;
  };
};

export type Booking = {
  id: number;
  ride_id: number;
  seats: number;
  total_amount: number;
  status: string;
  created_at: string;
  ride?: Ride;
  payment?: {
    id: number;
    provider: string;
    phone: string;
    amount: number;
    currency: string;
    status: string;
    external_ref: string | null;
  };
};

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("tafiya_token");
  return token
    ? { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }
    : { "Content-Type": "application/json" };
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { ...authHeaders(), ...(init?.headers || {}) },
  });
  if (!res.ok) {
    let detail = "Erreur réseau";
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      /* ignore */
    }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; app: string }>("/health"),
  cities: () => request<City[]>("/cities"),
  rides: (params: URLSearchParams) => request<Ride[]>(`/rides?${params}`),
  ride: (id: number) => request<Ride>(`/rides/${id}`),
  register: (body: Record<string, unknown>) =>
    request<{ access_token: string }>("/auth/register", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  login: (body: Record<string, unknown>) =>
    request<{ access_token: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  me: () => request<User>("/me"),
  publishRide: (body: Record<string, unknown>) =>
    request<Ride>("/rides", { method: "POST", body: JSON.stringify(body) }),
  book: (rideId: number, body: Record<string, unknown>) =>
    request<Booking>(`/rides/${rideId}/book`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  myBookings: () => request<Booking[]>("/me/bookings"),
  myRides: () => request<Ride[]>("/me/rides"),
  confirmPayment: (paymentId: number, success = true) =>
    request(`/payments/${paymentId}/confirm`, {
      method: "POST",
      body: JSON.stringify({ success }),
    }),
  providers: () => request<string[]>("/payments/providers"),
};

export const MODE_LABELS: Record<Ride["mode"], string> = {
  carpool: "Covoiturage",
  bush_taxi: "Taxi brousse",
  bus: "Bus",
};

export function formatXof(amount: number): string {
  return new Intl.NumberFormat("fr-FR").format(amount) + " F CFA";
}