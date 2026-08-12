import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../widgets/duo_card.dart';
import 'lesson_screen.dart';

class TrackScreen extends StatelessWidget {
  const TrackScreen({super.key, required this.api, required this.track});

  final ItLingoApi api;
  final Track track;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(track.title)),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          DuoCard(
            color: Color(int.parse(track.color.replaceFirst('#', '0xff'))).withOpacity(0.12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(track.title, style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w900)),
                const SizedBox(height: 8),
                Text(track.description),
              ],
            ),
          ),
          const SizedBox(height: 20),
          for (final unit in track.units) _UnitSection(api: api, unit: unit),
        ],
      ),
    );
  }
}

class _UnitSection extends StatelessWidget {
  const _UnitSection({required this.api, required this.unit});

  final ItLingoApi api;
  final Unit unit;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(unit.title, style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w800)),
          const SizedBox(height: 4),
          Text(unit.description),
          const SizedBox(height: 12),
          for (final lesson in unit.lessons)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: DuoCard(
                onTap: () {
                  Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => LessonScreen(api: api, lesson: lesson)),
                  );
                },
                child: Row(
                  children: [
                    const CircleAvatar(child: Icon(Icons.play_arrow)),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(lesson.title, style: Theme.of(context).textTheme.titleMedium),
                          const SizedBox(height: 4),
                          Text('${lesson.challengeCount} défi(s) • ${lesson.summary}'),
                        ],
                      ),
                    ),
                    XpPill(xp: lesson.xpReward),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}
