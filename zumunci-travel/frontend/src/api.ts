const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000/api";
const TOKEN_KEY = "zumunci_token";

export type VerificationStatus = "unverified" | "pending" | "verified" | "rejected";

export type User = {
  id: number;
  phone: string;
  full_name: string;
  role: string;
  city: string | null;
  is_verified: boolean;
  verification_status: VerificationStatus;
  accepted_safety_charter: boolean;
  phone_verified: boolean;
  is_suspended: boolean;
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
  women_priority: boolean;
  night_departure: boolean;
  is_active: boolean;
  driver: {
    id: number;
    full_name: string;
    phone: string | null;
    is_verified: boolean;
    verification_status: VerificationStatus;
    city: string | null;
    contact_hidden: boolean;
  };
};

export type Booking = {
  id: number;
  ride_id: number;
  seats: number;
  total_amount: number;
  platform_fee: number;
  driver_amount: number;
  status: string;
  contact_unlocked: boolean;
  created_at: string;
  driver_phone?: string | null;
  passenger_phone?: string | null;
  driver_whatsapp_url?: string | null;
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

export type ProductConfig = {
  app: string;
  pilot_mode: boolean;
  pilot_hub: string;
  pilot_corridors: string[];
  commission_rate: number;
  currency: string;
  kyc_sla_hours: number;
  cash_allowed_modes: string[];
  night_start_hour: number;
  night_end_hour: number;
  default_locale: string;
  payment_providers: string[];
};

export type SafetyCharter = {
  title: string;
  version: string;
  rules: string[];
};

export type ContactReveal = {
  booking_id: number;
  contact_unlocked: boolean;
  driver_name: string | null;
  driver_phone: string | null;
  passenger_name: string | null;
  passenger_phone: string | null;
  driver_whatsapp_url: string | null;
  passenger_whatsapp_url: string | null;
  warning: string;
};

function authHeaders(): HeadersInit {
  const token = localStorage.getItem(TOKEN_KEY);
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
  productConfig: () => request<ProductConfig>("/product/config"),
  cities: () => request<City[]>("/cities"),
  charter: () => request<SafetyCharter>("/safety/charter"),
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
  acceptCharter: () =>
    request<User>("/me/accept-charter", {
      method: "POST",
      body: JSON.stringify({ accept: true }),
    }),
  submitVerification: (body: Record<string, unknown>) =>
    request<User>("/me/verification", {
      method: "POST",
      body: JSON.stringify(body),
    }),
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
  revealContact: (bookingId: number) => request<ContactReveal>(`/bookings/${bookingId}/contact`),
  report: (body: Record<string, unknown>) =>
    request("/safety/reports", { method: "POST", body: JSON.stringify(body) }),
  providers: () => request<string[]>("/payments/providers"),
  pendingVerifications: () => request<User[]>("/admin/verifications/pending"),
  reviewVerification: (userId: number, approve: boolean, notes?: string) =>
    request<User>(`/admin/verifications/${userId}/review`, {
      method: "POST",
      body: JSON.stringify({ approve, notes }),
    }),
};

export const MODE_LABELS: Record<Ride["mode"], string> = {
  carpool: "Covoiturage",
  bush_taxi: "Taxi brousse",
  bus: "Bus",
};

export const VERIF_LABELS: Record<VerificationStatus, string> = {
  unverified: "Non vérifié",
  pending: "En cours de vérification",
  verified: "Identité vérifiée",
  rejected: "Vérification rejetée",
};

export function formatXof(amount: number): string {
  return new Intl.NumberFormat("fr-FR").format(amount) + " F CFA";
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}