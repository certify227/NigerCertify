from django.db.models import Sum
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AnswerOption, Lesson, Track, UserProgress
from .serializers import (
    LessonDetailSerializer,
    LessonSubmissionSerializer,
    TrackSerializer,
    UserProgressSerializer,
)


class HealthCheckView(APIView):
    def get(self, request):
        return Response({"status": "ok", "service": "itquest-api"})


class TrackListView(generics.ListAPIView):
    serializer_class = TrackSerializer
    queryset = Track.objects.prefetch_related("lessons")


class LessonDetailView(generics.RetrieveAPIView):
    serializer_class = LessonDetailSerializer
    queryset = Lesson.objects.select_related("track").prefetch_related("questions__options")


class LessonSubmitView(APIView):
    def post(self, request, pk: int):
        lesson = get_object_or_404(
            Lesson.objects.prefetch_related("questions__options"),
            pk=pk,
        )
        serializer = LessonSubmissionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data["username"]
        submitted_answers = {
            answer["question_id"]: answer["option_id"]
            for answer in serializer.validated_data["answers"]
        }

        feedback = []
        score = 0
        questions = list(lesson.questions.all())
        question_ids = {question.id for question in questions}
        option_ids = [
            option_id
            for question_id, option_id in submitted_answers.items()
            if question_id in question_ids
        ]
        options_by_id = AnswerOption.objects.filter(id__in=option_ids).in_bulk()

        for question in questions:
            selected_option_id = submitted_answers.get(question.id)
            selected_option = options_by_id.get(selected_option_id)
            correct_option = next(
                (option for option in question.options.all() if option.is_correct),
                None,
            )
            is_correct = bool(
                selected_option
                and selected_option.question_id == question.id
                and selected_option.is_correct
            )
            if is_correct:
                score += 1

            feedback.append(
                {
                    "question_id": question.id,
                    "selected_option_id": selected_option_id,
                    "correct_option_id": correct_option.id if correct_option else None,
                    "is_correct": is_correct,
                    "explanation": question.explanation,
                }
            )

        max_score = len(questions)
        completed = max_score > 0 and score == max_score
        if completed:
            xp = lesson.xp_reward
        elif max_score:
            xp = round(lesson.xp_reward * (score / max_score))
        else:
            xp = 0

        progress, _ = UserProgress.objects.update_or_create(
            username=username,
            lesson=lesson,
            defaults={
                "score": score,
                "max_score": max_score,
                "xp": xp,
                "completed": completed,
            },
        )
        total_xp = (
            UserProgress.objects.filter(username=username).aggregate(total=Sum("xp"))["total"]
            or 0
        )

        return Response(
            {
                "progress": UserProgressSerializer(progress).data,
                "total_xp": total_xp,
                "feedback": feedback,
            },
            status=status.HTTP_200_OK,
        )


class UserProgressView(APIView):
    def get(self, request, username: str):
        progress = UserProgress.objects.filter(username=username).select_related(
            "lesson",
            "lesson__track",
        )
        total_xp = progress.aggregate(total=Sum("xp"))["total"] or 0
        return Response(
            {
                "username": username,
                "total_xp": total_xp,
                "lessons": UserProgressSerializer(progress, many=True).data,
            }
        )
