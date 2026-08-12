import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../app_state.dart';
import '../models.dart';
import '../theme.dart';
import 'lesson_screen.dart';

class CoursePathScreen extends StatefulWidget {
  final Course course;
  const CoursePathScreen({super.key, required this.course});

  @override
  State<CoursePathScreen> createState() => _CoursePathScreenState();
}

class _CoursePathScreenState extends State<CoursePathScreen> {
  late Future<CourseDetail> _future;

  @override
  void initState() {
    super.initState();
    _future = _load();
  }

  Future<CourseDetail> _load() {
    return context.read<AppState>().api.fetchCourse(widget.course.slug);
  }

  Future<void> _reload() async {
    setState(() => _future = _load());
    await _future;
  }

  Future<void> _openLesson(Lesson lesson) async {
    final result = await Navigator.of(context).push<bool>(
      MaterialPageRoute(builder: (_) => LessonScreen(lesson: lesson)),
    );
    if (result == true && mounted) {
      await context.read<AppState>().refreshUser();
      await _reload();
    }
  }

  @override
  Widget build(BuildContext context) {
    final color = hexToColor(widget.course.color);
    return Scaffold(
      appBar: AppBar(title: Text(widget.course.title)),
      body: FutureBuilder<CourseDetail>(
        future: _future,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snapshot.hasError) {
            return Center(child: Text('${snapshot.error}'));
          }
          final detail = snapshot.data!;
          bool previousCompleted = true; // first lesson always unlocked
          final children = <Widget>[];
          for (final unit in detail.units) {
            children.add(_UnitHeader(unit: unit, color: color));
            for (var i = 0; i < unit.lessons.length; i++) {
              final lesson = unit.lessons[i];
              final unlocked = previousCompleted;
              children.add(
                _LessonNode(
                  lesson: lesson,
                  color: color,
                  unlocked: unlocked,
                  alignRight: i.isOdd,
                  onTap: unlocked ? () => _openLesson(lesson) : null,
                ),
              );
              previousCompleted = lesson.completed;
            }
          }
          return RefreshIndicator(
            onRefresh: _reload,
            child: ListView(
              padding: const EdgeInsets.symmetric(vertical: 16),
              children: children,
            ),
          );
        },
      ),
    );
  }
}

class _UnitHeader extends StatelessWidget {
  final Unit unit;
  final Color color;
  const _UnitHeader({required this.unit, required this.color});

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 20, 16, 8),
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
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
          if (unit.description.isNotEmpty)
            Text(
              unit.description,
              style: TextStyle(color: Colors.white.withValues(alpha: 0.9)),
            ),
        ],
      ),
    );
  }
}

class _LessonNode extends StatelessWidget {
  final Lesson lesson;
  final Color color;
  final bool unlocked;
  final bool alignRight;
  final VoidCallback? onTap;

  const _LessonNode({
    required this.lesson,
    required this.color,
    required this.unlocked,
    required this.alignRight,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final nodeColor = lesson.completed
        ? AppColors.gold
        : unlocked
            ? color
            : AppColors.locked;
    final icon = lesson.completed
        ? Icons.check
        : unlocked
            ? Icons.star
            : Icons.lock;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 24),
      child: Align(
        alignment: alignRight ? Alignment.centerRight : Alignment.centerLeft,
        child: Column(
          children: [
            GestureDetector(
              onTap: onTap,
              child: Container(
                width: 72,
                height: 72,
                decoration: BoxDecoration(
                  color: nodeColor,
                  shape: BoxShape.circle,
                  boxShadow: [
                    if (unlocked)
                      BoxShadow(
                        color: nodeColor.withValues(alpha: 0.4),
                        blurRadius: 8,
                        offset: const Offset(0, 4),
                      ),
                  ],
                ),
                child: Icon(icon, color: Colors.white, size: 34),
              ),
            ),
            const SizedBox(height: 6),
            SizedBox(
              width: 110,
              child: Text(
                lesson.title,
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontWeight: FontWeight.w600,
                  color: unlocked ? AppColors.textDark : AppColors.textLight,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
