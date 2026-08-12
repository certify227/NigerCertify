import 'package:flutter/material.dart';

class UserProfile {
  final int id;
  final String username;
  final String email;
  final int xp;
  final int level;
  final int streak;
  final int hearts;
  final bool reminderEnabled;
  final int reminderHour;

  UserProfile({
    required this.id,
    required this.username,
    required this.email,
    required this.xp,
    required this.level,
    required this.streak,
    required this.hearts,
    this.reminderEnabled = false,
    this.reminderHour = 19,
  });

  factory UserProfile.fromJson(Map<String, dynamic> json) {
    return UserProfile(
      id: json['id'] as int,
      username: json['username'] as String,
      email: json['email'] as String? ?? '',
      xp: json['xp'] as int? ?? 0,
      level: json['level'] as int? ?? 1,
      streak: json['streak'] as int? ?? 0,
      hearts: json['hearts'] as int? ?? 5,
      reminderEnabled: json['reminder_enabled'] as bool? ?? false,
      reminderHour: json['reminder_hour'] as int? ?? 19,
    );
  }

  UserProfile copyWith({
    int? xp,
    int? level,
    int? streak,
    int? hearts,
    bool? reminderEnabled,
    int? reminderHour,
  }) {
    return UserProfile(
      id: id,
      username: username,
      email: email,
      xp: xp ?? this.xp,
      level: level ?? this.level,
      streak: streak ?? this.streak,
      hearts: hearts ?? this.hearts,
      reminderEnabled: reminderEnabled ?? this.reminderEnabled,
      reminderHour: reminderHour ?? this.reminderHour,
    );
  }
}

class Track {
  final int id;
  final String title;
  final String slug;
  final String description;
  final String icon;
  final String color;
  final int progressPercent;

  Track({
    required this.id,
    required this.title,
    required this.slug,
    required this.description,
    required this.icon,
    required this.color,
    required this.progressPercent,
  });

  factory Track.fromJson(Map<String, dynamic> json) {
    return Track(
      id: json['id'] as int,
      title: json['title'] as String,
      slug: json['slug'] as String,
      description: json['description'] as String? ?? '',
      icon: json['icon'] as String? ?? '💻',
      color: json['color'] as String? ?? '#58CC02',
      progressPercent: json['progress_percent'] as int? ?? 0,
    );
  }

  Color get colorValue =>
      Color(int.parse(color.replaceFirst('#', '0xFF')));
}

class Lesson {
  final int id;
  final String title;
  final String description;
  final int xpReward;
  final int exerciseCount;
  final bool completed;

  Lesson({
    required this.id,
    required this.title,
    required this.description,
    required this.xpReward,
    required this.exerciseCount,
    required this.completed,
  });

  factory Lesson.fromJson(Map<String, dynamic> json) {
    return Lesson(
      id: json['id'] as int,
      title: json['title'] as String,
      description: json['description'] as String? ?? '',
      xpReward: json['xp_reward'] as int? ?? 25,
      exerciseCount: json['exercise_count'] as int? ?? 0,
      completed: json['completed'] as bool? ?? false,
    );
  }
}

class Exercise {
  final int id;
  final String question;
  final String exerciseType;
  final String hint;
  final String starterCode;
  final List<Choice> choices;

  Exercise({
    required this.id,
    required this.question,
    required this.exerciseType,
    required this.hint,
    required this.starterCode,
    required this.choices,
  });

  factory Exercise.fromJson(Map<String, dynamic> json) {
    return Exercise(
      id: json['id'] as int,
      question: json['question'] as String,
      exerciseType: json['exercise_type'] as String,
      hint: json['hint'] as String? ?? '',
      starterCode: json['starter_code'] as String? ?? '',
      choices: (json['choices'] as List<dynamic>? ?? [])
          .map((c) => Choice.fromJson(c as Map<String, dynamic>))
          .toList(),
    );
  }
}

class Choice {
  final int id;
  final String text;

  Choice({required this.id, required this.text});

  factory Choice.fromJson(Map<String, dynamic> json) {
    return Choice(
      id: json['id'] as int,
      text: json['text'] as String,
    );
  }
}

class LessonDetail {
  final int id;
  final String title;
  final List<Exercise> exercises;

  LessonDetail({
    required this.id,
    required this.title,
    required this.exercises,
  });

  factory LessonDetail.fromJson(Map<String, dynamic> json) {
    return LessonDetail(
      id: json['id'] as int,
      title: json['title'] as String,
      exercises: (json['exercises'] as List<dynamic>)
          .map((e) => Exercise.fromJson(e as Map<String, dynamic>))
          .toList(),
    );
  }
}

class TrackDetail {
  final int id;
  final String title;
  final String slug;
  final String icon;
  final String color;
  final List<Unit> units;

  TrackDetail({
    required this.id,
    required this.title,
    required this.slug,
    required this.icon,
    required this.color,
    required this.units,
  });

  factory TrackDetail.fromJson(Map<String, dynamic> json) {
    return TrackDetail(
      id: json['id'] as int,
      title: json['title'] as String,
      slug: json['slug'] as String,
      icon: json['icon'] as String? ?? '💻',
      color: json['color'] as String? ?? '#58CC02',
      units: (json['units'] as List<dynamic>)
          .map((u) => Unit.fromJson(u as Map<String, dynamic>))
          .toList(),
    );
  }
}

class Unit {
  final int id;
  final String title;
  final List<Lesson> lessons;

  Unit({required this.id, required this.title, required this.lessons});

  factory Unit.fromJson(Map<String, dynamic> json) {
    return Unit(
      id: json['id'] as int,
      title: json['title'] as String,
      lessons: (json['lessons'] as List<dynamic>)
          .map((l) => Lesson.fromJson(l as Map<String, dynamic>))
          .toList(),
    );
  }
}

class Dashboard {
  final int xp;
  final int level;
  final int streak;
  final int hearts;
  final int lessonsCompletedToday;
  final int xpToday;

  Dashboard({
    required this.xp,
    required this.level,
    required this.streak,
    required this.hearts,
    required this.lessonsCompletedToday,
    required this.xpToday,
  });

  factory Dashboard.fromJson(Map<String, dynamic> json) {
    return Dashboard(
      xp: json['xp'] as int? ?? 0,
      level: json['level'] as int? ?? 1,
      streak: json['streak'] as int? ?? 0,
      hearts: json['hearts'] as int? ?? 5,
      lessonsCompletedToday: json['lessons_completed_today'] as int? ?? 0,
      xpToday: json['xp_today'] as int? ?? 0,
    );
  }
}

class SubmitResult {
  final bool correct;
  final int? xpGained;
  final int? heartsLeft;
  final String explanation;
  final bool lessonComplete;

  SubmitResult({
    required this.correct,
    this.xpGained,
    this.heartsLeft,
    required this.explanation,
    this.lessonComplete = false,
  });

  factory SubmitResult.fromJson(Map<String, dynamic> json) {
    return SubmitResult(
      correct: json['correct'] as bool,
      xpGained: json['xp_gained'] as int?,
      heartsLeft: json['hearts_left'] as int?,
      explanation: json['explanation'] as String? ?? '',
      lessonComplete: json['lesson_complete'] as bool? ?? false,
    );
  }

  Map<String, dynamic> toJson() => {
        'correct': correct,
        'xp_gained': xpGained,
        'hearts_left': heartsLeft,
        'explanation': explanation,
        'lesson_complete': lessonComplete,
      };
}

class RunCodeResult {
  final String stdout;
  final String stderr;
  final int exitCode;
  final bool success;

  RunCodeResult({
    required this.stdout,
    required this.stderr,
    required this.exitCode,
    required this.success,
  });

  factory RunCodeResult.fromJson(Map<String, dynamic> json) {
    return RunCodeResult(
      stdout: json['stdout'] as String? ?? '',
      stderr: json['stderr'] as String? ?? '',
      exitCode: json['exit_code'] as int? ?? 1,
      success: json['success'] as bool? ?? false,
    );
  }
}
