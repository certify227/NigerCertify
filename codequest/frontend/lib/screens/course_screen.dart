import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/models.dart';
import '../state/app_state.dart';
import '../theme.dart';
import 'lesson_screen.dart';

class CourseScreen extends StatefulWidget {
  final String slug;
  const CourseScreen({super.key, required this.slug});

  @override
  State<CourseScreen> createState() => _CourseScreenState();
}

class _CourseScreenState extends State<CourseScreen> {
  late Future<CourseDetail> _future;

  @override
  void initState() {
    super.initState();
    _future = _load();
  }

  Future<CourseDetail> _load() =>
      context.read<AppState>().api.courseDetail(widget.slug);

  Future<void> _reload() async {
    setState(() {
      _future = _load();
    });
    await _future;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Parcours')),
      body: FutureBuilder<CourseDetail>(
        future: _future,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snapshot.hasError) {
            return Center(child: Text('Erreur : ${snapshot.error}'));
          }
          final course = snapshot.data!;
          return ListView(
            padding: const EdgeInsets.all(16),
            children: [
              Text(
                '${course.icon}  ${course.title}',
                style: const TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.w800,
                  color: AppColors.textDark,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                course.description,
                style: const TextStyle(color: AppColors.muted),
              ),
              const SizedBox(height: 16),
              for (final unit in course.units)
                _UnitSection(
                  unit: unit,
                  color: AppColors.fromHex(course.color),
                  onLessonDone: _reload,
                ),
            ],
          );
        },
      ),
    );
  }
}

class _UnitSection extends StatelessWidget {
  final Unit unit;
  final Color color;
  final Future<void> Function() onLessonDone;

  const _UnitSection({
    required this.unit,
    required this.color,
    required this.onLessonDone,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: 16),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: color,
            borderRadius: BorderRadius.circular(16),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                unit.title,
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              if (unit.description.isNotEmpty) ...[
                const SizedBox(height: 4),
                Text(
                  unit.description,
                  style: TextStyle(color: Colors.white.withValues(alpha: 0.9)),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 12),
        for (var i = 0; i < unit.lessons.length; i++)
          _LessonNode(
            lesson: unit.lessons[i],
            color: color,
            alignEnd: i.isOdd,
            onLessonDone: onLessonDone,
          ),
      ],
    );
  }
}

class _LessonNode extends StatelessWidget {
  final LessonSummary lesson;
  final Color color;
  final bool alignEnd;
  final Future<void> Function() onLessonDone;

  const _LessonNode({
    required this.lesson,
    required this.color,
    required this.alignEnd,
    required this.onLessonDone,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Align(
        alignment: alignEnd ? Alignment.centerRight : Alignment.centerLeft,
        child: SizedBox(
          width: 260,
          child: Material(
            color: lesson.completed ? color : AppColors.surface,
            borderRadius: BorderRadius.circular(18),
            elevation: 2,
            child: InkWell(
              borderRadius: BorderRadius.circular(18),
              onTap: () async {
                await Navigator.of(context).push(
                  MaterialPageRoute(
                    builder: (_) => LessonScreen(lessonId: lesson.id),
                  ),
                );
                await onLessonDone();
              },
              child: Padding(
                padding: const EdgeInsets.all(14),
                child: Row(
                  children: [
                    CircleAvatar(
                      radius: 22,
                      backgroundColor: lesson.completed
                          ? Colors.white
                          : color.withValues(alpha: 0.15),
                      child: Icon(
                        lesson.completed ? Icons.check : Icons.star_rounded,
                        color: lesson.completed ? color : color,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            lesson.title,
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              fontSize: 16,
                              color: lesson.completed
                                  ? Colors.white
                                  : AppColors.textDark,
                            ),
                          ),
                          const SizedBox(height: 2),
                          Text(
                            '${lesson.exerciseCount} questions · +${lesson.xpReward} XP',
                            style: TextStyle(
                              fontSize: 12,
                              color: lesson.completed
                                  ? Colors.white70
                                  : AppColors.muted,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
