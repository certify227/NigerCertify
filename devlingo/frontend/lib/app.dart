import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

const backgroundColor = Color(0xFFF5F7FB);
const cardColor = Colors.white;

class DevLingoApp extends StatelessWidget {
  const DevLingoApp({super.key, required this.repository});

  final LearningRepository repository;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'DevLingo',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF2563EB),
          brightness: Brightness.light,
        ),
        scaffoldBackgroundColor: backgroundColor,
        useMaterial3: true,
      ),
      home: DashboardScreen(repository: repository),
    );
  }
}

abstract class LearningRepository {
  Future<DashboardData> fetchDashboard();

  Future<LessonDetail> fetchLesson(String slug);
}

class HttpLearningRepository implements LearningRepository {
  HttpLearningRepository(String baseUrl)
    : _baseUrl = baseUrl.replaceAll(RegExp(r'/$'), '');

  final String _baseUrl;

  @override
  Future<DashboardData> fetchDashboard() async {
    final response = await http.get(Uri.parse('$_baseUrl/dashboard/'));
    if (response.statusCode != 200) {
      throw Exception('Impossible de charger le tableau de bord.');
    }
    return DashboardData.fromJson(
      jsonDecode(response.body) as Map<String, dynamic>,
    );
  }

  @override
  Future<LessonDetail> fetchLesson(String slug) async {
    final response = await http.get(Uri.parse('$_baseUrl/lessons/$slug/'));
    if (response.statusCode != 200) {
      throw Exception('Impossible de charger la lecon.');
    }
    return LessonDetail.fromJson(
      jsonDecode(response.body) as Map<String, dynamic>,
    );
  }
}

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key, required this.repository});

  final LearningRepository repository;

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  late Future<DashboardData> _dashboardFuture;

  @override
  void initState() {
    super.initState();
    _dashboardFuture = widget.repository.fetchDashboard();
  }

  void _reload() {
    setState(() {
      _dashboardFuture = widget.repository.fetchDashboard();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: FutureBuilder<DashboardData>(
          future: _dashboardFuture,
          builder: (context, snapshot) {
            if (snapshot.connectionState != ConnectionState.done) {
              return const Center(child: CircularProgressIndicator());
            }

            if (snapshot.hasError) {
              return Center(
                child: Padding(
                  padding: const EdgeInsets.all(24),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(
                        Icons.cloud_off,
                        size: 56,
                        color: Colors.redAccent,
                      ),
                      const SizedBox(height: 16),
                      Text(
                        'Backend indisponible',
                        style: Theme.of(context).textTheme.headlineSmall,
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Lancez Django sur http://127.0.0.1:8000 puis rechargez.',
                        textAlign: TextAlign.center,
                        style: Theme.of(context).textTheme.bodyLarge,
                      ),
                      const SizedBox(height: 16),
                      FilledButton.icon(
                        onPressed: _reload,
                        icon: const Icon(Icons.refresh),
                        label: const Text('Reessayer'),
                      ),
                    ],
                  ),
                ),
              );
            }

            final dashboard = snapshot.data!;
            return LayoutBuilder(
              builder: (context, constraints) {
                final isWide = constraints.maxWidth >= 900;
                return Row(
                  children: [
                    if (isWide)
                      SizedBox(
                        width: 320,
                        child: StatsRail(
                          profile: dashboard.profile,
                          plan: dashboard.dailyPlan,
                        ),
                      ),
                    Expanded(
                      child: RefreshIndicator(
                        onRefresh: () async => _reload(),
                        child: ListView(
                          padding: const EdgeInsets.all(24),
                          children: [
                            if (!isWide)
                              StatsRail(
                                profile: dashboard.profile,
                                plan: dashboard.dailyPlan,
                              ),
                            const SizedBox(height: 24),
                            Text(
                              'Votre parcours du jour',
                              style: Theme.of(context).textTheme.headlineMedium
                                  ?.copyWith(fontWeight: FontWeight.bold),
                            ),
                            const SizedBox(height: 8),
                            Text(
                              'Un apprentissage type Duolingo, repense pour Python, Git et Linux.',
                              style: Theme.of(context).textTheme.bodyLarge
                                  ?.copyWith(color: Colors.black54),
                            ),
                            const SizedBox(height: 24),
                            Wrap(
                              spacing: 20,
                              runSpacing: 20,
                              children: dashboard.tracks
                                  .map(
                                    (track) => SizedBox(
                                      width: isWide ? 420 : double.infinity,
                                      child: TrackCard(
                                        track: track,
                                        onOpenLesson: () async {
                                          final nextLesson =
                                              track.nextLessonSlug;
                                          if (nextLesson == null) {
                                            return;
                                          }
                                          await Navigator.of(context).push(
                                            MaterialPageRoute<void>(
                                              builder: (_) => LessonScreen(
                                                repository: widget.repository,
                                                lessonSlug: nextLesson,
                                              ),
                                            ),
                                          );
                                          _reload();
                                        },
                                      ),
                                    ),
                                  )
                                  .toList(),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                );
              },
            );
          },
        ),
      ),
    );
  }
}

class StatsRail extends StatelessWidget {
  const StatsRail({super.key, required this.profile, required this.plan});

  final LearnerProfile profile;
  final DailyPlan plan;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.all(24),
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: const Color(0xFF0F172A),
        borderRadius: BorderRadius.circular(28),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'DevLingo',
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
              color: Colors.white,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 12),
          Text(
            'Bonjour ${profile.displayName}',
            style: Theme.of(
              context,
            ).textTheme.titleLarge?.copyWith(color: Colors.white),
          ),
          const SizedBox(height: 4),
          Text(
            profile.targetRole,
            style: Theme.of(
              context,
            ).textTheme.bodyLarge?.copyWith(color: Colors.white70),
          ),
          const SizedBox(height: 24),
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              MetricChip(
                icon: Icons.local_fire_department,
                label: '${profile.streakDays} jours',
              ),
              MetricChip(icon: Icons.bolt, label: '${profile.totalXp} XP'),
              MetricChip(
                icon: Icons.favorite,
                label: '${profile.hearts} coeurs',
              ),
            ],
          ),
          const SizedBox(height: 24),
          Text(
            'Plan quotidien',
            style: Theme.of(
              context,
            ).textTheme.titleMedium?.copyWith(color: Colors.white),
          ),
          const SizedBox(height: 8),
          Text(
            '${plan.goalMinutes} minutes - ${plan.recommendedFocus}',
            style: Theme.of(
              context,
            ).textTheme.bodyMedium?.copyWith(color: Colors.white70),
          ),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0x1AFFFFFF),
              borderRadius: BorderRadius.circular(20),
            ),
            child: Text(
              plan.callToAction,
              style: Theme.of(
                context,
              ).textTheme.titleMedium?.copyWith(color: Colors.white),
            ),
          ),
        ],
      ),
    );
  }
}

class MetricChip extends StatelessWidget {
  const MetricChip({super.key, required this.icon, required this.label});

  final IconData icon;
  final String label;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: const Color(0x1AFFFFFF),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: Colors.white, size: 18),
            const SizedBox(width: 8),
            Text(
              label,
              style: const TextStyle(
                color: Colors.white,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class TrackCard extends StatelessWidget {
  const TrackCard({super.key, required this.track, required this.onOpenLesson});

  final TrackData track;
  final VoidCallback onOpenLesson;

  @override
  Widget build(BuildContext context) {
    final gradient = LinearGradient(
      colors: [parseHex(track.colorStart), parseHex(track.colorEnd)],
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
    );
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: cardColor,
        borderRadius: BorderRadius.circular(28),
        boxShadow: const [
          BoxShadow(
            color: Color(0x140F172A),
            blurRadius: 24,
            offset: Offset(0, 12),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              gradient: gradient,
              borderRadius: BorderRadius.circular(24),
            ),
            child: Row(
              children: [
                const Icon(Icons.auto_awesome, color: Colors.white, size: 28),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        track.title,
                        style: Theme.of(context).textTheme.titleLarge?.copyWith(
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        track.description,
                        style: Theme.of(
                          context,
                        ).textTheme.bodyMedium?.copyWith(color: Colors.white70),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 18),
          Text(
            '${track.completedLessons}/${track.totalLessons} lecons completees - ${track.progressPercent}%',
            style: Theme.of(
              context,
            ).textTheme.bodyMedium?.copyWith(color: Colors.black54),
          ),
          const SizedBox(height: 10),
          ClipRRect(
            borderRadius: BorderRadius.circular(999),
            child: LinearProgressIndicator(
              value: track.progressPercent / 100,
              minHeight: 10,
              backgroundColor: const Color(0xFFE2E8F0),
              valueColor: AlwaysStoppedAnimation<Color>(
                parseHex(track.colorStart),
              ),
            ),
          ),
          const SizedBox(height: 18),
          ...track.lessons.map(
            (lesson) => Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: ListTile(
                contentPadding: EdgeInsets.zero,
                leading: CircleAvatar(
                  backgroundColor: statusColor(lesson.status).withAlpha(30),
                  child: Icon(
                    statusIcon(lesson.status),
                    color: statusColor(lesson.status),
                  ),
                ),
                title: Text(lesson.title),
                subtitle: Text(
                  '${lesson.estimatedMinutes} min - ${lesson.xpReward} XP',
                ),
                trailing: Text(
                  statusLabel(lesson.status),
                  style: TextStyle(
                    color: statusColor(lesson.status),
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(height: 6),
          FilledButton.icon(
            onPressed: track.nextLessonSlug == null ? null : onOpenLesson,
            icon: const Icon(Icons.play_arrow),
            label: Text(
              track.nextLessonSlug == null ? 'Parcours termine' : 'Continuer',
            ),
          ),
        ],
      ),
    );
  }
}

class LessonScreen extends StatelessWidget {
  const LessonScreen({
    super.key,
    required this.repository,
    required this.lessonSlug,
  });

  final LearningRepository repository;
  final String lessonSlug;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Lecon'),
        backgroundColor: backgroundColor,
      ),
      body: FutureBuilder<LessonDetail>(
        future: repository.fetchLesson(lessonSlug),
        builder: (context, snapshot) {
          if (snapshot.connectionState != ConnectionState.done) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snapshot.hasError) {
            return Center(
              child: Text(
                'Impossible de charger cette lecon.',
                style: Theme.of(context).textTheme.titleMedium,
              ),
            );
          }
          final lesson = snapshot.data!;
          return ListView(
            padding: const EdgeInsets.all(24),
            children: [
              Text(
                lesson.trackTitle,
                style: Theme.of(
                  context,
                ).textTheme.titleMedium?.copyWith(color: Colors.blueGrey),
              ),
              const SizedBox(height: 6),
              Text(
                lesson.title,
                style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                lesson.summary,
                style: Theme.of(
                  context,
                ).textTheme.bodyLarge?.copyWith(color: Colors.black54),
              ),
              const SizedBox(height: 18),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  LessonBadge(
                    icon: Icons.timer,
                    label: '${lesson.estimatedMinutes} min',
                  ),
                  LessonBadge(icon: Icons.bolt, label: '${lesson.xpReward} XP'),
                  LessonBadge(
                    icon: Icons.quiz,
                    label: '${lesson.challengeCount} exercices',
                  ),
                ],
              ),
              const SizedBox(height: 24),
              ...lesson.exercises.map(
                (exercise) => Container(
                  margin: const EdgeInsets.only(bottom: 16),
                  padding: const EdgeInsets.all(20),
                  decoration: BoxDecoration(
                    color: cardColor,
                    borderRadius: BorderRadius.circular(24),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Exercice ${exercise.sortOrder}',
                        style: Theme.of(context).textTheme.labelLarge?.copyWith(
                          color: Colors.blueGrey,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        exercise.prompt,
                        style: Theme.of(context).textTheme.titleMedium
                            ?.copyWith(fontWeight: FontWeight.w600),
                      ),
                      const SizedBox(height: 12),
                      ...exercise.options.map(
                        (option) => Padding(
                          padding: const EdgeInsets.only(bottom: 8),
                          child: DecoratedBox(
                            decoration: BoxDecoration(
                              color: const Color(0xFFF8FAFC),
                              borderRadius: BorderRadius.circular(16),
                              border: Border.all(
                                color: const Color(0xFFE2E8F0),
                              ),
                            ),
                            child: Padding(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 14,
                                vertical: 12,
                              ),
                              child: Row(
                                children: [
                                  const Icon(
                                    Icons.radio_button_unchecked,
                                    size: 18,
                                  ),
                                  const SizedBox(width: 10),
                                  Expanded(child: Text(option)),
                                ],
                              ),
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Reponse attendue : ${exercise.correctAnswer}',
                        style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: Colors.green.shade700,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        exercise.explanation,
                        style: Theme.of(
                          context,
                        ).textTheme.bodyMedium?.copyWith(color: Colors.black54),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }
}

class LessonBadge extends StatelessWidget {
  const LessonBadge({super.key, required this.icon, required this.label});

  final IconData icon;
  final String label;

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(999),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 18, color: Colors.blueGrey.shade700),
            const SizedBox(width: 8),
            Text(label),
          ],
        ),
      ),
    );
  }
}

class DashboardData {
  DashboardData({
    required this.profile,
    required this.dailyPlan,
    required this.tracks,
  });

  factory DashboardData.fromJson(Map<String, dynamic> json) {
    return DashboardData(
      profile: LearnerProfile.fromJson(json['profile'] as Map<String, dynamic>),
      dailyPlan: DailyPlan.fromJson(json['daily_plan'] as Map<String, dynamic>),
      tracks: (json['tracks'] as List<dynamic>)
          .map((track) => TrackData.fromJson(track as Map<String, dynamic>))
          .toList(),
    );
  }

  final LearnerProfile profile;
  final DailyPlan dailyPlan;
  final List<TrackData> tracks;
}

class LearnerProfile {
  LearnerProfile({
    required this.displayName,
    required this.targetRole,
    required this.dailyGoalMinutes,
    required this.streakDays,
    required this.totalXp,
    required this.hearts,
  });

  factory LearnerProfile.fromJson(Map<String, dynamic> json) {
    return LearnerProfile(
      displayName: json['display_name'] as String,
      targetRole: json['target_role'] as String,
      dailyGoalMinutes: json['daily_goal_minutes'] as int,
      streakDays: json['streak_days'] as int,
      totalXp: json['total_xp'] as int,
      hearts: json['hearts'] as int,
    );
  }

  final String displayName;
  final String targetRole;
  final int dailyGoalMinutes;
  final int streakDays;
  final int totalXp;
  final int hearts;
}

class DailyPlan {
  DailyPlan({
    required this.goalMinutes,
    required this.recommendedFocus,
    required this.callToAction,
  });

  factory DailyPlan.fromJson(Map<String, dynamic> json) {
    return DailyPlan(
      goalMinutes: json['goal_minutes'] as int,
      recommendedFocus: json['recommended_focus'] as String,
      callToAction: json['cta'] as String,
    );
  }

  final int goalMinutes;
  final String recommendedFocus;
  final String callToAction;
}

class TrackData {
  TrackData({
    required this.title,
    required this.description,
    required this.colorStart,
    required this.colorEnd,
    required this.completedLessons,
    required this.totalLessons,
    required this.progressPercent,
    required this.lessons,
  });

  factory TrackData.fromJson(Map<String, dynamic> json) {
    return TrackData(
      title: json['title'] as String,
      description: json['description'] as String,
      colorStart: json['color_start'] as String,
      colorEnd: json['color_end'] as String,
      completedLessons: json['completed_lessons'] as int,
      totalLessons: json['total_lessons'] as int,
      progressPercent: json['progress_percent'] as int,
      lessons: (json['lessons'] as List<dynamic>)
          .map(
            (lesson) => LessonPreview.fromJson(lesson as Map<String, dynamic>),
          )
          .toList(),
    );
  }

  final String title;
  final String description;
  final String colorStart;
  final String colorEnd;
  final int completedLessons;
  final int totalLessons;
  final int progressPercent;
  final List<LessonPreview> lessons;

  String? get nextLessonSlug {
    for (final lesson in lessons) {
      if (lesson.status == 'available' || lesson.status == 'completed') {
        return lesson.slug;
      }
    }
    return null;
  }
}

class LessonPreview {
  LessonPreview({
    required this.title,
    required this.slug,
    required this.estimatedMinutes,
    required this.xpReward,
    required this.status,
  });

  factory LessonPreview.fromJson(Map<String, dynamic> json) {
    return LessonPreview(
      title: json['title'] as String,
      slug: json['slug'] as String,
      estimatedMinutes: json['estimated_minutes'] as int,
      xpReward: json['xp_reward'] as int,
      status: json['status'] as String,
    );
  }

  final String title;
  final String slug;
  final int estimatedMinutes;
  final int xpReward;
  final String status;
}

class LessonDetail {
  LessonDetail({
    required this.title,
    required this.summary,
    required this.trackTitle,
    required this.estimatedMinutes,
    required this.xpReward,
    required this.challengeCount,
    required this.exercises,
  });

  factory LessonDetail.fromJson(Map<String, dynamic> json) {
    return LessonDetail(
      title: json['title'] as String,
      summary: json['summary'] as String,
      trackTitle: json['track_title'] as String,
      estimatedMinutes: json['estimated_minutes'] as int,
      xpReward: json['xp_reward'] as int,
      challengeCount: json['challenge_count'] as int,
      exercises: (json['exercises'] as List<dynamic>)
          .map(
            (exercise) =>
                ExerciseItem.fromJson(exercise as Map<String, dynamic>),
          )
          .toList(),
    );
  }

  final String title;
  final String summary;
  final String trackTitle;
  final int estimatedMinutes;
  final int xpReward;
  final int challengeCount;
  final List<ExerciseItem> exercises;
}

class ExerciseItem {
  ExerciseItem({
    required this.prompt,
    required this.options,
    required this.correctAnswer,
    required this.explanation,
    required this.sortOrder,
  });

  factory ExerciseItem.fromJson(Map<String, dynamic> json) {
    return ExerciseItem(
      prompt: json['prompt'] as String,
      options: (json['options'] as List<dynamic>)
          .map((option) => option.toString())
          .toList(),
      correctAnswer: json['correct_answer'] as String,
      explanation: json['explanation'] as String,
      sortOrder: json['sort_order'] as int,
    );
  }

  final String prompt;
  final List<String> options;
  final String correctAnswer;
  final String explanation;
  final int sortOrder;
}

Color parseHex(String value) {
  final normalized = value.replaceFirst('#', '');
  return Color(int.parse('FF$normalized', radix: 16));
}

Color statusColor(String status) {
  switch (status) {
    case 'completed':
      return Colors.green;
    case 'available':
      return Colors.orange;
    default:
      return Colors.blueGrey;
  }
}

IconData statusIcon(String status) {
  switch (status) {
    case 'completed':
      return Icons.check_circle;
    case 'available':
      return Icons.play_circle_fill;
    default:
      return Icons.lock;
  }
}

String statusLabel(String status) {
  switch (status) {
    case 'completed':
      return 'Termine';
    case 'available':
      return 'Pret';
    default:
      return 'Bloque';
  }
}
