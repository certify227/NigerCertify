class Track {
  const Track({
    required this.id,
    required this.slug,
    required this.title,
    required this.description,
    required this.icon,
    required this.color,
    required this.units,
  });

  final int id;
  final String slug;
  final String title;
  final String description;
  final String icon;
  final String color;
  final List<Unit> units;

  factory Track.fromJson(Map<String, dynamic> json) {
    return Track(
      id: json['id'] as int,
      slug: json['slug'] as String,
      title: json['title'] as String,
      description: json['description'] as String,
      icon: json['icon'] as String,
      color: json['color'] as String,
      units: (json['units'] as List<dynamic>).map((item) => Unit.fromJson(item as Map<String, dynamic>)).toList(),
    );
  }
}

class Unit {
  const Unit({
    required this.id,
    required this.title,
    required this.description,
    required this.lessons,
  });

  final int id;
  final String title;
  final String description;
  final List<LessonSummary> lessons;

  factory Unit.fromJson(Map<String, dynamic> json) {
    return Unit(
      id: json['id'] as int,
      title: json['title'] as String,
      description: json['description'] as String,
      lessons: (json['lessons'] as List<dynamic>)
          .map((item) => LessonSummary.fromJson(item as Map<String, dynamic>))
          .toList(),
    );
  }
}

class LessonSummary {
  const LessonSummary({
    required this.id,
    required this.title,
    required this.summary,
    required this.xpReward,
    required this.challengeCount,
  });

  final int id;
  final String title;
  final String summary;
  final int xpReward;
  final int challengeCount;

  factory LessonSummary.fromJson(Map<String, dynamic> json) {
    return LessonSummary(
      id: json['id'] as int,
      title: json['title'] as String,
      summary: json['summary'] as String,
      xpReward: json['xp_reward'] as int,
      challengeCount: json['challenge_count'] as int? ?? 0,
    );
  }
}

class LessonDetail {
  const LessonDetail({
    required this.id,
    required this.title,
    required this.summary,
    required this.xpReward,
    required this.challenges,
  });

  final int id;
  final String title;
  final String summary;
  final int xpReward;
  final List<Challenge> challenges;

  factory LessonDetail.fromJson(Map<String, dynamic> json) {
    return LessonDetail(
      id: json['id'] as int,
      title: json['title'] as String,
      summary: json['summary'] as String,
      xpReward: json['xp_reward'] as int,
      challenges: (json['challenges'] as List<dynamic>)
          .map((item) => Challenge.fromJson(item as Map<String, dynamic>))
          .toList(),
    );
  }
}

class Challenge {
  const Challenge({
    required this.id,
    required this.type,
    required this.prompt,
    required this.choices,
    required this.explanation,
  });

  final int id;
  final String type;
  final String prompt;
  final List<dynamic> choices;
  final String explanation;

  factory Challenge.fromJson(Map<String, dynamic> json) {
    return Challenge(
      id: json['id'] as int,
      type: json['type'] as String,
      prompt: json['prompt'] as String,
      choices: json['choices'] as List<dynamic>,
      explanation: json['explanation'] as String,
    );
  }
}

class AttemptResult {
  const AttemptResult({
    required this.isCorrect,
    required this.explanation,
    required this.correctAnswer,
    required this.earnedXp,
    required this.lessonCompleted,
  });

  final bool isCorrect;
  final String explanation;
  final dynamic correctAnswer;
  final int earnedXp;
  final bool lessonCompleted;

  factory AttemptResult.fromJson(Map<String, dynamic> json) {
    return AttemptResult(
      isCorrect: json['is_correct'] as bool,
      explanation: json['explanation'] as String,
      correctAnswer: json['correct_answer'],
      earnedXp: json['earned_xp'] as int,
      lessonCompleted: json['lesson_completed'] as bool,
    );
  }
}
