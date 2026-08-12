from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from .models import AnswerOption, Lesson, Question, Track, UserProgress


class LearningApiTests(APITestCase):
    def setUp(self):
        self.track = Track.objects.create(
            title="Python débutant",
            slug="python-debutant",
            description="Bases Python",
            order=1,
        )
        self.lesson = Lesson.objects.create(
            track=self.track,
            title="Variables",
            summary="Comprendre les variables",
            xp_reward=20,
            order=1,
        )
        self.question = Question.objects.create(
            lesson=self.lesson,
            prompt="Quelle syntaxe affecte une variable ?",
            explanation="Python utilise le signe = pour affecter une valeur.",
            order=1,
        )
        self.correct_option = AnswerOption.objects.create(
            question=self.question,
            text="name = 'Ada'",
            is_correct=True,
            order=1,
        )
        self.wrong_option = AnswerOption.objects.create(
            question=self.question,
            text="string name = 'Ada'",
            is_correct=False,
            order=2,
        )

    def test_tracks_endpoint_returns_nested_lessons(self):
        response = self.client.get(reverse("track-list"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["title"], "Python débutant")
        self.assertEqual(response.data[0]["lessons"][0]["title"], "Variables")

    def test_lesson_submit_scores_and_persists_progress(self):
        response = self.client.post(
            reverse("lesson-submit", args=[self.lesson.id]),
            {
                "username": "amina",
                "answers": [
                    {
                        "question_id": self.question.id,
                        "option_id": self.correct_option.id,
                    }
                ],
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["progress"]["score"], 1)
        self.assertEqual(response.data["progress"]["xp"], 20)
        self.assertTrue(response.data["progress"]["completed"])
        self.assertTrue(UserProgress.objects.filter(username="amina").exists())

    def test_lesson_submit_rejects_option_from_another_question(self):
        other_question = Question.objects.create(
            lesson=self.lesson,
            prompt="Question séparée",
            order=2,
        )
        foreign_option = AnswerOption.objects.create(
            question=other_question,
            text="Mauvaise question",
            is_correct=True,
            order=1,
        )

        response = self.client.post(
            reverse("lesson-submit", args=[self.lesson.id]),
            {
                "username": "amina",
                "answers": [
                    {
                        "question_id": self.question.id,
                        "option_id": foreign_option.id,
                    },
                    {
                        "question_id": other_question.id,
                        "option_id": foreign_option.id,
                    },
                ],
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["progress"]["score"], 1)
        self.assertFalse(response.data["feedback"][0]["is_correct"])
        self.assertTrue(response.data["feedback"][1]["is_correct"])

    def test_progress_endpoint_returns_total_xp(self):
        UserProgress.objects.create(
            username="amina",
            lesson=self.lesson,
            score=1,
            max_score=1,
            xp=20,
            completed=True,
        )

        response = self.client.get(reverse("user-progress", args=["amina"]))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["total_xp"], 20)
        self.assertEqual(response.data["lessons"][0]["lesson_title"], "Variables")
