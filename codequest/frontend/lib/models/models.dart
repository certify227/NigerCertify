// Plain data models mirroring the Django REST API payloads.

class Profile {
  final String username;
  final int xp;
  final int streak;
  final int hearts;
  final int level;

  const Profile({
    required this.username,
    required this.xp,
    required this.streak,
    required this.hearts,
    required this.level,
  });

  factory Profile.fromJson(Map<String, dynamic> json) => Profile(
        username: json['username'] as String? ?? '',
        xp: json['xp'] as int? ?? 0,
        streak: json['streak'] as int? ?? 0,
        hearts: json['hearts'] as int? ?? 0,
        level: json['level'] as int? ?? 1,
      );
}

class Course {
  final int id;
  final String title;
  final String slug;
  final String description;
  final String icon;
  final String color;

  const Course({
    required this.id,
    required this.title,
    required this.slug,
    required this.description,
    required this.icon,
    required this.color,
  });

  factory Course.fromJson(Map<String, dynamic> json) => Course(
        id: json['id'] as int,
        title: json['title'] as String,
        slug: json['slug'] as String,
        description: json['description'] as String? ?? '',
        icon: json['icon'] as String? ?? 'quiz',
        color: json['color'] as String? ?? '#58CC02',
      );
}

class LessonSummary {
  final int id;
  final String title;
  final int order;
  final int xpReward;
  final int exerciseCount;
  final bool completed;

  const LessonSummary({
    required this.id,
    required this.title,
    required this.order,
    required this.xpReward,
    required this.exerciseCount,
    required this.completed,
  });

  factory LessonSummary.fromJson(Map<String, dynamic> json) => LessonSummary(
        id: json['id'] as int,
        title: json['title'] as String,
        order: json['order'] as int? ?? 0,
        xpReward: json['xp_reward'] as int? ?? 10,
        exerciseCount: json['exercise_count'] as int? ?? 0,
        completed: json['completed'] as bool? ?? false,
      );
}

class Unit {
  final int id;
  final String title;
  final String description;
  final List<LessonSummary> lessons;

  const Unit({
    required this.id,
    required this.title,
    required this.description,
    required this.lessons,
  });

  factory Unit.fromJson(Map<String, dynamic> json) => Unit(
        id: json['id'] as int,
        title: json['title'] as String,
        description: json['description'] as String? ?? '',
        lessons: (json['lessons'] as List<dynamic>? ?? [])
            .map((e) => LessonSummary.fromJson(e as Map<String, dynamic>))
            .toList(),
      );
}

class CourseDetail {
  final int id;
  final String title;
  final String slug;
  final String description;
  final String icon;
  final String color;
  final List<Unit> units;

  const CourseDetail({
    required this.id,
    required this.title,
    required this.slug,
    required this.description,
    required this.icon,
    required this.color,
    required this.units,
  });

  factory CourseDetail.fromJson(Map<String, dynamic> json) => CourseDetail(
        id: json['id'] as int,
        title: json['title'] as String,
        slug: json['slug'] as String,
        description: json['description'] as String? ?? '',
        icon: json['icon'] as String? ?? 'quiz',
        color: json['color'] as String? ?? '#58CC02',
        units: (json['units'] as List<dynamic>? ?? [])
            .map((e) => Unit.fromJson(e as Map<String, dynamic>))
            .toList(),
      );
}

class Exercise {
  final int id;
  final String kind; // multiple_choice | true_false | fill_blank
  final String prompt;
  final List<String> choices;

  const Exercise({
    required this.id,
    required this.kind,
    required this.prompt,
    required this.choices,
  });

  factory Exercise.fromJson(Map<String, dynamic> json) => Exercise(
        id: json['id'] as int,
        kind: json['kind'] as String? ?? 'multiple_choice',
        prompt: json['prompt'] as String,
        choices: (json['choices'] as List<dynamic>? ?? [])
            .map((e) => e.toString())
            .toList(),
      );
}

class Lesson {
  final int id;
  final String title;
  final int xpReward;
  final List<Exercise> exercises;

  const Lesson({
    required this.id,
    required this.title,
    required this.xpReward,
    required this.exercises,
  });

  factory Lesson.fromJson(Map<String, dynamic> json) => Lesson(
        id: json['id'] as int,
        title: json['title'] as String,
        xpReward: json['xp_reward'] as int? ?? 10,
        exercises: (json['exercises'] as List<dynamic>? ?? [])
            .map((e) => Exercise.fromJson(e as Map<String, dynamic>))
            .toList(),
      );
}

class ExerciseResult {
  final int exerciseId;
  final bool correct;
  final String expected;
  final String explanation;

  const ExerciseResult({
    required this.exerciseId,
    required this.correct,
    required this.expected,
    required this.explanation,
  });

  factory ExerciseResult.fromJson(Map<String, dynamic> json) => ExerciseResult(
        exerciseId: json['exercise_id'] as int,
        correct: json['correct'] as bool? ?? false,
        expected: json['expected'] as String? ?? '',
        explanation: json['explanation'] as String? ?? '',
      );
}

class SubmissionResult {
  final bool passed;
  final int correctCount;
  final int total;
  final int earnedXp;
  final List<ExerciseResult> results;
  final Profile profile;

  const SubmissionResult({
    required this.passed,
    required this.correctCount,
    required this.total,
    required this.earnedXp,
    required this.results,
    required this.profile,
  });

  factory SubmissionResult.fromJson(Map<String, dynamic> json) =>
      SubmissionResult(
        passed: json['passed'] as bool? ?? false,
        correctCount: json['correct_count'] as int? ?? 0,
        total: json['total'] as int? ?? 0,
        earnedXp: json['earned_xp'] as int? ?? 0,
        results: (json['results'] as List<dynamic>? ?? [])
            .map((e) => ExerciseResult.fromJson(e as Map<String, dynamic>))
            .toList(),
        profile: Profile.fromJson(json['profile'] as Map<String, dynamic>),
      );
}

class LeaderboardEntry {
  final String username;
  final int xp;
  final int level;
  final int streak;

  const LeaderboardEntry({
    required this.username,
    required this.xp,
    required this.level,
    required this.streak,
  });

  factory LeaderboardEntry.fromJson(Map<String, dynamic> json) =>
      LeaderboardEntry(
        username: json['username'] as String? ?? '',
        xp: json['xp'] as int? ?? 0,
        level: json['level'] as int? ?? 1,
        streak: json['streak'] as int? ?? 0,
      );
}
