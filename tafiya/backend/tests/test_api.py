from datetime import date, timedelta


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["country"] == "NE"
    assert data["currency"] == "XOF"


def test_cities_seeded(client):
    r = client.get("/api/cities")
    assert r.status_code == 200
    names = {c["name"] for c in r.json()}
    assert "Niamey" in names
    assert "Maradi" in names
    assert "Agadez" in names


def test_search_and_book_flow(client):
    login = client.post(
        "/api/auth/login",
        json={"phone": "+22790000002", "password": "tafiya123"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    rides = client.get("/api/rides", params={"origin": "Niamey", "destination": "Maradi"})
    assert rides.status_code == 200
    assert len(rides.json()) >= 1
    ride_id = rides.json()[0]["id"]

    booking = client.post(
        f"/api/rides/{ride_id}/book",
        headers=headers,
        json={"seats": 1, "payment_provider": "orange_money"},
    )
    assert booking.status_code == 201
    body = booking.json()
    assert body["status"] == "pending"
    assert body["payment"]["provider"] == "orange_money"
    payment_id = body["payment"]["id"]

    confirm = client.post(
        f"/api/payments/{payment_id}/confirm",
        headers=headers,
        json={"success": True},
    )
    assert confirm.status_code == 200
    assert confirm.json()["status"] == "success"


def test_publish_ride(client):
    login = client.post(
        "/api/auth/login",
        json={"phone": "90000001", "password": "tafiya123"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]

    r = client.post(
        "/api/rides",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "origin_city": "Niamey",
            "destination_city": "Tillabéri",
            "departure_date": str(date.today() + timedelta(days=5)),
            "departure_time": "09:00",
            "seats_total": 2,
            "price_per_seat": 2500,
            "mode": "carpool",
            "meeting_point": "Katako",
        },
    )
    assert r.status_code == 201
    assert r.json()["destination_city"] == "Tillabéri"