import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../api/endpoints.dart';
import '../models/course.dart';
import '../state/auth_state.dart';
import '../theme/app_theme.dart';
import 'lesson_screen.dart';

class CourseDetailScreen extends StatefulWidget {
  const CourseDetailScreen({super.key, required this.slug});
  final String slug;

  @override
  State<CourseDetailScreen> createState() => _CourseDetailScreenState();
}

class _CourseDetailScreenState extends State<CourseDetailScreen> {
  late Future<Course> _future;

  @override
  void initState() {
    super.initState();
    _future = _load();
  }

  Future<Course> _load() =>
      CoursesApi(context.read<AuthState>().client).detail(widget.slug);

  Future<void> _refresh() async {
    setState(() => _future = _load());
    await _future;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Parcours')),
      body: FutureBuilder<Course>(
        future: _future,
        builder: (context, snap) {
          if (snap.connectionState != ConnectionState.done) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snap.hasError || !snap.hasData) {
            return Center(child: Text('Erreur : ${snap.error}'));
          }
          final course = snap.data!;
          return RefreshIndicator(
            onRefresh: _refresh,
            child: ListView(
              padding: const EdgeInsets.all(16),
              children: [
                Row(
                  children: [
                    Text(course.icon, style: const TextStyle(fontSize: 40)),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(course.title,
                              style: const TextStyle(
                                  fontSize: 22, fontWeight: FontWeight.w900)),
                          Text(course.description,
                              style: const TextStyle(
                                  color: AppColors.textSecondary)),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                ...course.modules.map((m) => _ModuleSection(module: m)),
              ],
            ),
          );
        },
      ),
    );
  }
}

class _ModuleSection extends StatelessWidget {
  const _ModuleSection({required this.module});
  final Module module;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const SizedBox(height: 16),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          decoration: BoxDecoration(
            color: AppColors.primary,
            borderRadius: BorderRadius.circular(12),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Module ${module.order + 1}',
                  style: const TextStyle(
                      color: Colors.white70, fontWeight: FontWeight.w700)),
              Text(module.title,
                  style: const TextStyle(
                      color: Colors.white,
                      fontSize: 18,
                      fontWeight: FontWeight.w900)),
            ],
          ),
        ),
        const SizedBox(height: 12),
        ...module.lessons.map((l) => _LessonRow(lesson: l)),
      ],
    );
  }
}

class _LessonRow extends StatelessWidget {
  const _LessonRow({required this.lesson});
  final LessonSummary lesson;

  @override
  Widget build(BuildContext context) {
    final color = lesson.isCompleted ? AppColors.primary : AppColors.secondary;
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Card(
        child: InkWell(
          borderRadius: BorderRadius.circular(16),
          onTap: () async {
            final refreshed = await Navigator.of(context).push<bool>(
              MaterialPageRoute(
                builder: (_) => LessonScreen(lessonId: lesson.id),
              ),
            );
            if (refreshed == true && context.mounted) {
              // Redemander la liste pour mettre à jour l'état "complété".
              (context.findAncestorStateOfType<_CourseDetailScreenState>())
                  ?._refresh();
            }
          },
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                Container(
                  width: 44,
                  height: 44,
                  alignment: Alignment.center,
                  decoration: BoxDecoration(
                    color: color.withOpacity(0.15),
                    shape: BoxShape.circle,
                  ),
                  child: Icon(
                    lesson.isCompleted ? Icons.check : Icons.play_arrow,
                    color: color,
                  ),
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(lesson.title,
                          style: const TextStyle(
                              fontSize: 16, fontWeight: FontWeight.w800)),
                      Text(
                        '${lesson.exerciseCount} exercices · ${lesson.xpReward} XP',
                        style: const TextStyle(
                            color: AppColors.textSecondary, fontSize: 12),
                      ),
                    ],
                  ),
                ),
                if (lesson.isCompleted)
                  const Icon(Icons.emoji_events, color: AppColors.warning),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
