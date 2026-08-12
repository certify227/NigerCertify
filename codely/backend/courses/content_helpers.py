"""Helpers pour créer rapidement des exercices."""

from courses.models import Choice, Exercise, Lesson, Track, Unit


def create_track(title, slug, description, icon, color, order):
    return Track.objects.create(
        title=title,
        slug=slug,
        description=description,
        icon=icon,
        color=color,
        order=order,
        is_published=True,
    )


def create_unit(track, title, description, order):
    return Unit.objects.create(track=track, title=title, description=description, order=order)


def create_lesson(unit, title, description, order, xp_reward=25):
    return Lesson.objects.create(
        unit=unit,
        title=title,
        description=description,
        order=order,
        xp_reward=xp_reward,
    )


def add_mc(lesson, question, options, order, hint="", explanation=""):
    """options: list of (text, is_correct)"""
    ex = Exercise.objects.create(
        lesson=lesson,
        question=question,
        exercise_type="multiple_choice",
        hint=hint,
        explanation=explanation,
        order=order,
    )
    Choice.objects.bulk_create([
        Choice(exercise=ex, text=t, is_correct=c, order=i)
        for i, (t, c) in enumerate(options)
    ])
    return ex


def add_tf(lesson, question, is_true, order, hint="", explanation=""):
    ex = Exercise.objects.create(
        lesson=lesson,
        question=question,
        exercise_type="true_false",
        hint=hint,
        explanation=explanation,
        order=order,
    )
    Choice.objects.bulk_create([
        Choice(exercise=ex, text="Vrai", is_correct=is_true, order=0),
        Choice(exercise=ex, text="Faux", is_correct=not is_true, order=1),
    ])
    return ex


def add_fill(lesson, question, answer, order, hint="", explanation=""):
    return Exercise.objects.create(
        lesson=lesson,
        question=question,
        exercise_type="fill_blank",
        correct_answer=answer,
        hint=hint,
        explanation=explanation,
        order=order,
    )


def add_code(lesson, question, starter_code, correct_answer, order, hint="", explanation=""):
    return Exercise.objects.create(
        lesson=lesson,
        question=question,
        exercise_type="code_challenge",
        starter_code=starter_code,
        correct_answer=correct_answer,
        hint=hint,
        explanation=explanation,
        order=order,
    )
