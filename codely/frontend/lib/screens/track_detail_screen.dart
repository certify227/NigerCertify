import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/models.dart';
import '../providers/app_state.dart';
import '../theme/app_theme.dart';
import 'lesson_screen.dart';

class TrackDetailScreen extends StatefulWidget {
  final String slug;
  final String title;

  const TrackDetailScreen({super.key, required this.slug, required this.title});

  @override
  State<TrackDetailScreen> createState() => _TrackDetailScreenState();
}

class _TrackDetailScreenState extends State<TrackDetailScreen> {
  TrackDetail? _track;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final api = context.read<AppState>().api;
    final track = await api.getTrackDetail(widget.slug);
    if (mounted) {
      setState(() {
        _track = track;
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.title)),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView.builder(
              padding: const EdgeInsets.all(16),
              itemCount: _track!.units.length,
              itemBuilder: (context, unitIndex) {
                final unit = _track!.units[unitIndex];
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Padding(
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      child: Text(
                        unit.title,
                        style: Theme.of(context).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w800),
                      ),
                    ),
                    ...unit.lessons.asMap().entries.map((entry) {
                      final i = entry.key;
                      final lesson = entry.value;
                      return _LessonNode(
                        lesson: lesson,
                        index: i,
                        onTap: () async {
                          await Navigator.of(context).push(
                            MaterialPageRoute(
                              builder: (_) => LessonScreen(lessonId: lesson.id, title: lesson.title),
                            ),
                          );
                          _load();
                          if (context.mounted) context.read<AppState>().refresh();
                        },
                      );
                    }),
                    const SizedBox(height: 16),
                  ],
                );
              },
            ),
    );
  }
}

class _LessonNode extends StatelessWidget {
  final Lesson lesson;
  final int index;
  final VoidCallback onTap;

  const _LessonNode({required this.lesson, required this.index, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final color = lesson.completed ? AppTheme.primaryGreen : AppTheme.primaryBlue;
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: EdgeInsets.only(left: index.isEven ? 0 : 40, right: index.isEven ? 40 : 0, bottom: 16),
        child: Column(
          children: [
            Container(
              width: 72,
              height: 72,
              decoration: BoxDecoration(
                color: color,
                shape: BoxShape.circle,
                boxShadow: [
                  BoxShadow(color: color.withOpacity(0.4), offset: const Offset(0, 4), blurRadius: 0),
                ],
                border: Border.all(color: Colors.white, width: 4),
              ),
              child: Icon(
                lesson.completed ? Icons.check : Icons.play_arrow,
                color: Colors.white,
                size: 32,
              ),
            ),
            const SizedBox(height: 6),
            Text(
              lesson.title,
              textAlign: TextAlign.center,
              style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 13),
            ),
            Text('+${lesson.xpReward} XP', style: const TextStyle(color: AppTheme.textMuted, fontSize: 11)),
          ],
        ),
      ),
    );
  }
}
