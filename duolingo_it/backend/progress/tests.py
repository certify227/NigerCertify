from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from courses.models import Choice, Course, Exercise, Lesson, Module

User = get_user_model()


class SubmissionFlowTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="bob", email="bob@example.com", password="s3cret!"
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

        course = Course.objects.create(title="C", slug="c", order=0)
        module = Module.objects.create(course=course, title="M", order=0)
        self.lesson = Lesson.objects.create(
            module=module, title="L", order=0, xp_reward=25
        )
        self.mcq = Exercise.objects.create(
            lesson=self.lesson, kind="mcq", prompt="?", order=0
        )
        self.correct_choice = Choice.objects.create(
            exercise=self.mcq, text="A", is_correct=True, order=0
        )
        Choice.objects.create(
            exercise=self.mcq, text="B", is_correct=False, order=1
        )
        self.tf = Exercise.objects.create(
            lesson=self.lesson,
            kind="true_false",
            prompt="?",
            correct_answer="true",
            order=1,
        )

    def test_full_correct_awards_xp(self):
        resp = self.client.post(
            f"/api/v1/lessons/{self.lesson.id}/submit/",
            {
                "answers": [
                    {"exercise_id": self.mcq.id, "answer": str(self.correct_choice.id)},
                    {"exercise_id": self.tf.id, "answer": "true"},
                ]
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["passed"])
        self.assertEqual(body["xp_earned"], 25)
        self.user.refresh_from_db()
        self.assertEqual(self.user.xp, 25)
        self.assertEqual(self.user.streak, 1)

    def test_wrong_answer_loses_heart_and_no_xp(self):
        start_hearts = self.user.hearts
        resp = self.client.post(
            f"/api/v1/lessons/{self.lesson.id}/submit/",
            {
                "answers": [
                    {"exercise_id": self.mcq.id, "answer": "999"},
                    {"exercise_id": self.tf.id, "answer": "false"},
                ]
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertFalse(body["passed"])
        self.assertEqual(body["xp_earned"], 0)
        self.user.refresh_from_db()
        self.assertEqual(self.user.xp, 0)
        self.assertLess(self.user.hearts, start_hearts)

    def test_lesson_detail_hides_correct_answers(self):
        resp = self.client.get(f"/api/v1/lessons/{self.lesson.id}/")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        for ex in payload["exercises"]:
            for choice in ex["choices"]:
                self.assertNotIn("is_correct", choice)
            self.assertNotIn("correct_answer", ex)
