// Data models mirroring the CodeLingo REST API payloads.

class AppUser {
  final int id;
  final String username;
  final String email;
  final int xp;
  final int gems;
  final int hearts;
  final int streakCount;
  final int dailyGoalXp;
  final String avatar;

  AppUser({
    required this.id,
    required this.username,
    required this.email,
    required this.xp,
    required this.gems,
    required this.hearts,
    required this.streakCount,
    required this.dailyGoalXp,
    required this.avatar,
  });

  factory AppUser.fromJson(Map<String, dynamic> json) {
    return AppUser(
      id: json['id'] ?? 0,
      username: json['username'] ?? '',
      email: json['email'] ?? '',
      xp: json['xp'] ?? 0,
      gems: json['gems'] ?? 0,
      hearts: json['hearts'] ?? 0,
      streakCount: json['streak_count'] ?? 0,
      dailyGoalXp: json['daily_goal_xp'] ?? 50,
      avatar: json['avatar'] ?? '🦉',
    );
  }
}

class Course {
  final int id;
  final String title;
  final String slug;
  final String subtitle;
  final String description;
  final String icon;
  final String color;
  final int unitCount;

  Course({
    required this.id,
    required this.title,
    required this.slug,
    required this.subtitle,
    required this.description,
    required this.icon,
    required this.color,
    required this.unitCount,
  });

  factory Course.fromJson(Map<String, dynamic> json) {
    return Course(
      id: json['id'],
      title: json['title'] ?? '',
      slug: json['slug'] ?? '',
      subtitle: json['subtitle'] ?? '',
      description: json['description'] ?? '',
      icon: json['icon'] ?? '💻',
      color: json['color'] ?? '#58CC02',
      unitCount: json['unit_count'] ?? 0,
    );
  }
}

class Unit {
  final int id;
  final String title;
  final String description;
  final List<Lesson> lessons;

  Unit({
    required this.id,
    required this.title,
    required this.description,
    required this.lessons,
  });

  factory Unit.fromJson(Map<String, dynamic> json) {
    return Unit(
      id: json['id'],
      title: json['title'] ?? '',
      description: json['description'] ?? '',
      lessons: (json['lessons'] as List<dynamic>? ?? [])
          .map((e) => Lesson.fromJson(e))
          .toList(),
    );
  }
}

class Lesson {
  final int id;
  final String title;
  final int xpReward;
  final int exerciseCount;
  final bool completed;
  final int bestScore;

  Lesson({
    required this.id,
    required this.title,
    required this.xpReward,
    required this.exerciseCount,
    required this.completed,
    required this.bestScore,
  });

  factory Lesson.fromJson(Map<String, dynamic> json) {
    return Lesson(
      id: json['id'],
      title: json['title'] ?? '',
      xpReward: json['xp_reward'] ?? 10,
      exerciseCount: json['exercise_count'] ?? 0,
      completed: json['completed'] ?? false,
      bestScore: json['best_score'] ?? 0,
    );
  }
}

class Exercise {
  final int id;
  final String type;
  final String question;
  final List<String> choices;
  final String correctAnswer;
  final String explanation;

  Exercise({
    required this.id,
    required this.type,
    required this.question,
    required this.choices,
    required this.correctAnswer,
    required this.explanation,
  });

  factory Exercise.fromJson(Map<String, dynamic> json) {
    return Exercise(
      id: json['id'],
      type: json['exercise_type'] ?? 'multiple_choice',
      question: json['question'] ?? '',
      choices:
          (json['choices'] as List<dynamic>? ?? []).map((e) => '$e').toList(),
      correctAnswer: json['correct_answer'] ?? '',
      explanation: json['explanation'] ?? '',
    );
  }
}

class CourseDetail extends Course {
  final List<Unit> units;

  CourseDetail({
    required super.id,
    required super.title,
    required super.slug,
    required super.subtitle,
    required super.description,
    required super.icon,
    required super.color,
    required super.unitCount,
    required this.units,
  });

  factory CourseDetail.fromJson(Map<String, dynamic> json) {
    return CourseDetail(
      id: json['id'],
      title: json['title'] ?? '',
      slug: json['slug'] ?? '',
      subtitle: json['subtitle'] ?? '',
      description: json['description'] ?? '',
      icon: json['icon'] ?? '💻',
      color: json['color'] ?? '#58CC02',
      unitCount: json['unit_count'] ?? 0,
      units: (json['units'] as List<dynamic>? ?? [])
          .map((e) => Unit.fromJson(e))
          .toList(),
    );
  }
}

class LessonResult {
  final int score;
  final int correct;
  final int total;
  final bool passed;
  final int xpGained;

  LessonResult({
    required this.score,
    required this.correct,
    required this.total,
    required this.passed,
    required this.xpGained,
  });

  factory LessonResult.fromJson(Map<String, dynamic> json) {
    return LessonResult(
      score: json['score'] ?? 0,
      correct: json['correct'] ?? 0,
      total: json['total'] ?? 0,
      passed: json['passed'] ?? false,
      xpGained: json['xp_gained'] ?? 0,
    );
  }
}

class LeaderboardEntry {
  final int rank;
  final String username;
  final String avatar;
  final int xp;
  final int streakCount;

  LeaderboardEntry({
    required this.rank,
    required this.username,
    required this.avatar,
    required this.xp,
    required this.streakCount,
  });

  factory LeaderboardEntry.fromJson(Map<String, dynamic> json) {
    return LeaderboardEntry(
      rank: json['rank'] ?? 0,
      username: json['username'] ?? '',
      avatar: json['avatar'] ?? '🦉',
      xp: json['xp'] ?? 0,
      streakCount: json['streak_count'] ?? 0,
    );
  }
}
