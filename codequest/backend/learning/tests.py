"""Tests for the CodeQuest API."""

from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from .models import Course, Exercise, Lesson, Profile, Unit


class AuthTests(APITestCase):
    def test_register_creates_user_profile_and_token(self):
        resp = self.client.post(
            reverse("register"),
            {"username": "alice", "email": "a@x.io", "password": "S3cur3Pass!"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertIn("token", resp.data)
        self.assertTrue(User.objects.filter(username="alice").exists())
        self.assertTrue(Profile.objects.filter(user__username="alice").exists())

    def test_login_returns_token(self):
        User.objects.create_user("bob", password="S3cur3Pass!")
        resp = self.client.post(
            reverse("login"),
            {"username": "bob", "password": "S3cur3Pass!"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("token", resp.data)

    def test_login_rejects_bad_credentials(self):
        User.objects.create_user("carol", password="S3cur3Pass!")
        resp = self.client.post(
            reverse("login"),
            {"username": "carol", "password": "wrong"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_me_requires_authentication(self):
        resp = self.client.get(reverse("me"))
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)


class ContentApiTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user("dave", password="S3cur3Pass!")
        self.client.force_authenticate(self.user)
        self.course = Course.objects.create(title="Python", slug="python")
        self.unit = Unit.objects.create(course=self.course, title="Bases")
        self.lesson = Lesson.objects.create(
            unit=self.unit, title="Variables", xp_reward=15
        )
        self.q1 = Exercise.objects.create(
            lesson=self.lesson,
            kind=Exercise.Kind.MULTIPLE_CHOICE,
            prompt="1+1 ?",
            choices=["1", "2", "3"],
            answer="2",
            order=0,
        )
        self.q2 = Exercise.objects.create(
            lesson=self.lesson,
            kind=Exercise.Kind.FILL_BLANK,
            prompt="print ?",
            answer="print",
            order=1,
        )

    def test_course_list(self):
        resp = self.client.get(reverse("course-list"))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(resp.data), 1)

    def test_course_detail_includes_units_and_lessons(self):
        resp = self.client.get(
            reverse("course-detail", args=[self.course.slug])
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(resp.data["units"]), 1)
        self.assertEqual(len(resp.data["units"][0]["lessons"]), 1)

    def test_lesson_detail_hides_answers(self):
        resp = self.client.get(reverse("lesson-detail", args=[self.lesson.id]))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertNotIn("answer", resp.data["exercises"][0])

    def test_submit_all_correct_awards_xp(self):
        resp = self.client.post(
            reverse("lesson-submit", args=[self.lesson.id]),
            {"answers": {str(self.q1.id): "2", str(self.q2.id): "PRINT"}},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertTrue(resp.data["passed"])
        self.assertEqual(resp.data["earned_xp"], 15)
        self.assertEqual(resp.data["profile"]["xp"], 15)
        self.assertEqual(resp.data["profile"]["streak"], 1)

    def test_submit_wrong_answer_loses_heart(self):
        resp = self.client.post(
            reverse("lesson-submit", args=[self.lesson.id]),
            {"answers": {str(self.q1.id): "3", str(self.q2.id): "print"}},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertFalse(resp.data["passed"])
        self.assertEqual(resp.data["earned_xp"], 0)
        self.assertEqual(resp.data["profile"]["hearts"], Profile.MAX_HEARTS - 1)

    def test_xp_not_awarded_twice(self):
        payload = {"answers": {str(self.q1.id): "2", str(self.q2.id): "print"}}
        self.client.post(
            reverse("lesson-submit", args=[self.lesson.id]), payload, format="json"
        )
        resp = self.client.post(
            reverse("lesson-submit", args=[self.lesson.id]), payload, format="json"
        )
        self.assertTrue(resp.data["passed"])
        self.assertEqual(resp.data["earned_xp"], 0)
        self.assertEqual(resp.data["profile"]["xp"], 15)

    def test_leaderboard(self):
        profile = self.user.profile
        profile.xp = 120
        profile.save()
        resp = self.client.get(reverse("leaderboard"))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data[0]["username"], "dave")
        self.assertEqual(resp.data[0]["level"], 2)


class ModelTests(APITestCase):
    def test_exercise_is_correct_is_case_insensitive(self):
        course = Course.objects.create(title="X", slug="x")
        unit = Unit.objects.create(course=course, title="U")
        lesson = Lesson.objects.create(unit=unit, title="L")
        ex = Exercise.objects.create(
            lesson=lesson, prompt="?", answer="Vrai"
        )
        self.assertTrue(ex.is_correct("vrai"))
        self.assertTrue(ex.is_correct("  VRAI  "))
        self.assertFalse(ex.is_correct("faux"))

    def test_profile_level(self):
        user = User.objects.create_user("eve", password="S3cur3Pass!")
        profile = user.profile
        profile.xp = 250
        self.assertEqual(profile.level, 3)
