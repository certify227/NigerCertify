from datetime import date, timedelta


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["app"] == "ZumunciTravel"
    assert data["country"] == "NE"
    assert data["currency"] == "XOF"


def test_cities_seeded(client):
    r = client.get("/api/cities")
    assert r.status_code == 200
    names = {c["name"] for c in r.json()}
    assert "Niamey" in names
    assert "Maradi" in names
    assert "Agadez" in names


def test_phone_hidden_until_payment(client):
    rides = client.get("/api/rides", params={"origin": "Niamey", "destination": "Maradi"})
    assert rides.status_code == 200
    assert len(rides.json()) >= 1
    driver = rides.json()[0]["driver"]
    assert driver["contact_hidden"] is True
    assert driver["phone"] != "+22790000001"
    assert "•" in driver["phone"]


def test_unverified_cannot_book(client):
    login = client.post(
        "/api/auth/login",
        json={"phone": "90000004", "password": "zumunci123"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    rides = client.get("/api/rides", params={"origin": "Niamey", "destination": "Maradi"})
    ride_id = rides.json()[0]["id"]
    booking = client.post(
        f"/api/rides/{ride_id}/book",
        headers={"Authorization": f"Bearer {token}"},
        json={"seats": 1, "payment_provider": "orange_money"},
    )
    assert booking.status_code == 403


def test_verified_book_unlocks_contact(client):
    login = client.post(
        "/api/auth/login",
        json={"phone": "+22790000002", "password": "zumunci123"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    rides = client.get("/api/rides", params={"origin": "Niamey", "destination": "Maradi"})
    ride_id = rides.json()[0]["id"]

    booking = client.post(
        f"/api/rides/{ride_id}/book",
        headers=headers,
        json={"seats": 1, "payment_provider": "orange_money"},
    )
    assert booking.status_code == 201
    body = booking.json()
    assert body["contact_unlocked"] is False
    assert body["driver_phone"] is None
    payment_id = body["payment"]["id"]

    confirm = client.post(
        f"/api/payments/{payment_id}/confirm",
        headers=headers,
        json={"success": True},
    )
    assert confirm.status_code == 200

    contact = client.get(f"/api/bookings/{body['id']}/contact", headers=headers)
    assert contact.status_code == 200
    assert contact.json()["contact_unlocked"] is True
    assert contact.json()["driver_phone"] == "+22790000001"


def test_verification_and_admin_approve(client):
    reg = client.post(
        "/api/auth/register",
        json={
            "phone": "90111222",
            "full_name": "Fatima Test",
            "password": "zumunci123",
            "city": "Niamey",
            "accept_safety_charter": True,
        },
    )
    assert reg.status_code == 201
    token = reg.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    submit = client.post(
        "/api/me/verification",
        headers=headers,
        json={
            "id_document_type": "national_id",
            "id_document_number": "NE-CNI-998877",
            "id_full_name": "Fatima Test",
            "accept_safety_charter": True,
        },
    )
    assert submit.status_code == 200
    assert submit.json()["verification_status"] == "pending"
    user_id = submit.json()["id"]

    admin_login = client.post(
        "/api/auth/login",
        json={"phone": "90000099", "password": "zumunci123"},
    )
    admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}
    review = client.post(
        f"/api/admin/verifications/{user_id}/review",
        headers=admin_headers,
        json={"approve": True, "notes": "OK"},
    )
    assert review.status_code == 200
    assert review.json()["verification_status"] == "verified"
    assert review.json()["is_verified"] is True


def test_publish_ride_verified(client):
    login = client.post(
        "/api/auth/login",
        json={"phone": "90000001", "password": "zumunci123"},
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


def test_safety_report(client):
    login = client.post(
        "/api/auth/login",
        json={"phone": "90000002", "password": "zumunci123"},
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    report = client.post(
        "/api/safety/reports",
        headers=headers,
        json={
            "reported_user_id": 1,
            "reason": "scam",
            "details": "Demande de paiement hors plateforme par Orange Money personnel.",
        },
    )
    assert report.status_code == 201
    assert report.json()["reason"] == "scam"