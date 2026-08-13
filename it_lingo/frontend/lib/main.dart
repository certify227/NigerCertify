import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const ItLingoApp());
}

class ItLingoApp extends StatelessWidget {
  const ItLingoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'ItLingo',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF58CC02)),
        scaffoldBackgroundColor: const Color(0xFFF7F7F7),
        useMaterial3: true,
      ),
      home: const DashboardScreen(),
    );
  }
}

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  late Future<DashboardData> _future;

  @override
  void initState() {
    super.initState();
    _future = ItLingoApi().fetchDashboard();
  }

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final isDesktop = constraints.maxWidth >= 980;
        return Scaffold(
          appBar: AppBar(
            title: const Text('ItLingo'),
            actions: const [
              Padding(
                padding: EdgeInsets.only(right: 16),
                child: Center(
                  child: Chip(
                    label: Text('Serie: 12 jours'),
                    avatar: Icon(Icons.local_fire_department),
                  ),
                ),
              ),
            ],
          ),
          bottomNavigationBar: isDesktop
              ? null
              : NavigationBar(
                  height: 72,
                  selectedIndex: 0,
                  destinations: const [
                    NavigationDestination(icon: Icon(Icons.home_outlined), label: 'Accueil'),
                    NavigationDestination(
                      icon: Icon(Icons.route_outlined),
                      label: 'Parcours',
                    ),
                    NavigationDestination(
                      icon: Icon(Icons.person_outline),
                      label: 'Profil',
                    ),
                  ],
                ),
          body: Row(
            children: [
              if (isDesktop)
                NavigationRail(
                  selectedIndex: 0,
                  labelType: NavigationRailLabelType.all,
                  destinations: const [
                    NavigationRailDestination(
                      icon: Icon(Icons.home_outlined),
                      selectedIcon: Icon(Icons.home),
                      label: Text('Accueil'),
                    ),
                    NavigationRailDestination(
                      icon: Icon(Icons.route_outlined),
                      selectedIcon: Icon(Icons.route),
                      label: Text('Parcours'),
                    ),
                    NavigationRailDestination(
                      icon: Icon(Icons.person_outline),
                      selectedIcon: Icon(Icons.person),
                      label: Text('Profil'),
                    ),
                  ],
                ),
              Expanded(
                child: FutureBuilder<DashboardData>(
                  future: _future,
                  builder: (context, snapshot) {
                    if (snapshot.connectionState != ConnectionState.done) {
                      return const Center(child: CircularProgressIndicator());
                    }
                    if (snapshot.hasError) {
                      return _ErrorState(error: snapshot.error.toString());
                    }
                    final data = snapshot.data ?? DashboardData.fallback();
                    return SingleChildScrollView(
                      padding: EdgeInsets.fromLTRB(16, 16, 16, isDesktop ? 16 : 160),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Wrap(
                            spacing: 16,
                            runSpacing: 16,
                            children: [
                              _MetricCard(
                                title: 'Objectif XP',
                                value: '${data.dailyXpTarget}',
                                icon: Icons.emoji_events,
                              ),
                              _MetricCard(
                                title: 'Objectif serie',
                                value: '${data.streakGoal} min',
                                icon: Icons.timer_outlined,
                              ),
                              _MetricCard(
                                title: 'Parcours actifs',
                                value: '${data.tracks.length}',
                                icon: Icons.route,
                              ),
                            ],
                          ),
                          const SizedBox(height: 24),
                          if (data.dailyChallenge != null) ...[
                            Text(
                              'Challenge du jour',
                              style: Theme.of(context).textTheme.headlineSmall,
                            ),
                            const SizedBox(height: 12),
                            _DailyChallengeCard(challenge: data.dailyChallenge!),
                            const SizedBox(height: 24),
                          ],
                          Text(
                            'Parcours disponibles',
                            style: Theme.of(context).textTheme.headlineSmall,
                          ),
                          const SizedBox(height: 12),
                          ...data.tracks.map((track) => _TrackCard(track: track, isDesktop: isDesktop)),
                          if (!isDesktop) const SizedBox(height: 96),
                        ],
                      ),
                    );
                  },
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _MetricCard extends StatelessWidget {
  const _MetricCard({
    required this.title,
    required this.value,
    required this.icon,
  });

  final String title;
  final String value;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 220,
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon),
              const SizedBox(height: 12),
              Text(title, style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 4),
              Text(value, style: Theme.of(context).textTheme.headlineSmall),
            ],
          ),
        ),
      ),
    );
  }
}

class _DailyChallengeCard extends StatelessWidget {
  const _DailyChallengeCard({required this.challenge});

  final DailyChallenge challenge;

  @override
  Widget build(BuildContext context) {
    return Card(
      color: const Color(0xFFFFF6D6),
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(challenge.title, style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 8),
            Text(challenge.prompt),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                Chip(label: Text(challenge.difficulty)),
                Chip(label: Text('${challenge.estimatedMinutes} min')),
                if (challenge.trackSlug != null)
                  Chip(label: Text(_compactTrackLabel(challenge.trackSlug!))),
              ],
            ),
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: () {},
              icon: const Icon(Icons.play_arrow),
              label: const Text('Commencer'),
            ),
          ],
        ),
      ),
    );
  }
}

class _TrackCard extends StatelessWidget {
  const _TrackCard({required this.track, required this.isDesktop});

  final TrackSummary track;
  final bool isDesktop;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: isDesktop
            ? Row(
                children: [
                  _TrackAvatar(color: track.colorTheme),
                  const SizedBox(width: 18),
                  Expanded(child: _TrackContent(track: track)),
                  FilledButton(
                    onPressed: () {},
                    child: const Text('Continuer'),
                  ),
                ],
              )
            : Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _TrackAvatar(color: track.colorTheme),
                  const SizedBox(height: 12),
                  _TrackContent(track: track),
                  const SizedBox(height: 16),
                  FilledButton(
                    onPressed: () {},
                    child: const Text('Continuer'),
                  ),
                ],
              ),
      ),
    );
  }
}

class _TrackAvatar extends StatelessWidget {
  const _TrackAvatar({required this.color});

  final Color color;

  @override
  Widget build(BuildContext context) {
    return CircleAvatar(
      radius: 28,
      backgroundColor: color,
      child: const Icon(Icons.code, color: Colors.white),
    );
  }
}

class _TrackContent extends StatelessWidget {
  const _TrackContent({required this.track});

  final TrackSummary track;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(track.title, style: Theme.of(context).textTheme.titleLarge),
        const SizedBox(height: 6),
        Text(track.summary),
        const SizedBox(height: 10),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            Chip(label: Text(track.level)),
            Chip(label: Text('${track.estimatedMinutes} min')),
            Chip(label: Text('${track.moduleCount} modules')),
            Chip(label: Text('${track.lessonCount} lecons')),
          ],
        ),
      ],
    );
  }
}

class _ErrorState extends StatelessWidget {
  const _ErrorState({required this.error});

  final String error;

  @override
  Widget build(BuildContext context) {
    final fallback = DashboardData.fallback();
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.cloud_off, size: 48),
              const SizedBox(height: 16),
              Text(
                'Connexion API indisponible, affichage d\'un jeu de donnees local.',
                style: Theme.of(context).textTheme.titleMedium,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              Text(
                error,
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall,
              ),
              const SizedBox(height: 16),
              FilledButton(
                onPressed: () {
                  Navigator.of(context).pushReplacement(
                    MaterialPageRoute<void>(
                      builder: (_) => FallbackDashboardScreen(data: fallback),
                    ),
                  );
                },
                child: const Text('Charger la maquette locale'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class FallbackDashboardScreen extends StatelessWidget {
  const FallbackDashboardScreen({super.key, required this.data});

  final DashboardData data;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('ItLingo - maquette locale')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 160),
        children: [
          if (data.dailyChallenge != null) _DailyChallengeCard(challenge: data.dailyChallenge!),
          const SizedBox(height: 16),
          ...data.tracks.map((track) => _TrackCard(track: track, isDesktop: false)),
          const SizedBox(height: 96),
        ],
      ),
    );
  }
}

class ItLingoApi {
  ItLingoApi({
    http.Client? client,
    this.baseUrl = 'http://192.168.137.135:8000/api/v1',
  }) : _client = client ?? http.Client();

  final http.Client _client;
  final String baseUrl;

  Future<DashboardData> fetchDashboard() async {
    final response = await _client.get(Uri.parse('$baseUrl/dashboard/'));
    if (response.statusCode != 200) {
      throw Exception('Dashboard request failed with status ${response.statusCode}');
    }

    final payload = jsonDecode(response.body) as Map<String, dynamic>;
    return DashboardData.fromJson(payload);
  }
}

class DashboardData {
  DashboardData({
    required this.streakGoal,
    required this.dailyXpTarget,
    required this.tracks,
    required this.dailyChallenge,
  });

  final int streakGoal;
  final int dailyXpTarget;
  final List<TrackSummary> tracks;
  final DailyChallenge? dailyChallenge;

  factory DashboardData.fromJson(Map<String, dynamic> json) {
    return DashboardData(
      streakGoal: json['streak_goal'] as int? ?? 20,
      dailyXpTarget: json['daily_xp_target'] as int? ?? 50,
      tracks: (json['tracks'] as List<dynamic>? ?? [])
          .map((entry) => TrackSummary.fromJson(entry as Map<String, dynamic>))
          .toList(),
      dailyChallenge: json['daily_challenge'] == null
          ? null
          : DailyChallenge.fromJson(json['daily_challenge'] as Map<String, dynamic>),
    );
  }

  factory DashboardData.fallback() {
    return DashboardData(
      streakGoal: 20,
      dailyXpTarget: 50,
      tracks: [
        TrackSummary(
          title: 'Fondamentaux Python',
          slug: 'python-foundations',
          summary: 'Variables, conditions, boucles et fonctions en micro-lecons.',
          level: 'beginner',
          estimatedMinutes: 12,
          colorTheme: const Color(0xFF4C9AFF),
          moduleCount: 2,
          lessonCount: 3,
        ),
        TrackSummary(
          title: 'Algorithmes',
          slug: 'algorithms',
          summary: 'Complexite, structures de donnees et patterns classiques.',
          level: 'intermediate',
          estimatedMinutes: 18,
          colorTheme: const Color(0xFFFF9600),
          moduleCount: 1,
          lessonCount: 1,
        ),
      ],
      dailyChallenge: DailyChallenge(
        title: 'Challenge du jour',
        prompt: 'Ecris une boucle qui affiche les nombres pairs de 2 a 10.',
        difficulty: 'easy',
        estimatedMinutes: 4,
        trackSlug: 'python-foundations',
      ),
    );
  }
}

class TrackSummary {
  TrackSummary({
    required this.title,
    required this.slug,
    required this.summary,
    required this.level,
    required this.estimatedMinutes,
    required this.colorTheme,
    required this.moduleCount,
    required this.lessonCount,
  });

  final String title;
  final String slug;
  final String summary;
  final String level;
  final int estimatedMinutes;
  final Color colorTheme;
  final int moduleCount;
  final int lessonCount;

  factory TrackSummary.fromJson(Map<String, dynamic> json) {
    return TrackSummary(
      title: json['title'] as String? ?? 'Parcours',
      slug: json['slug'] as String? ?? '',
      summary: json['summary'] as String? ?? '',
      level: json['level'] as String? ?? 'beginner',
      estimatedMinutes: json['estimated_minutes'] as int? ?? 0,
      colorTheme: _colorFromHex(json['color_theme'] as String? ?? '#58CC02'),
      moduleCount: json['module_count'] as int? ?? 0,
      lessonCount: json['lesson_count'] as int? ?? 0,
    );
  }
}

class DailyChallenge {
  DailyChallenge({
    required this.title,
    required this.prompt,
    required this.difficulty,
    required this.estimatedMinutes,
    required this.trackSlug,
  });

  final String title;
  final String prompt;
  final String difficulty;
  final int estimatedMinutes;
  final String? trackSlug;

  factory DailyChallenge.fromJson(Map<String, dynamic> json) {
    return DailyChallenge(
      title: json['title'] as String? ?? 'Challenge',
      prompt: json['prompt'] as String? ?? '',
      difficulty: json['difficulty'] as String? ?? 'easy',
      estimatedMinutes: json['estimated_minutes'] as int? ?? 0,
      trackSlug: json['track'] as String?,
    );
  }
}

Color _colorFromHex(String hexColor) {
  final buffer = StringBuffer();
  if (hexColor.length == 7) {
    buffer.write('ff');
  }
  buffer.write(hexColor.replaceFirst('#', ''));
  return Color(int.parse(buffer.toString(), radix: 16));
}

String _compactTrackLabel(String slug) {
  final parts = slug
      .split('-')
      .where((part) => part.isNotEmpty)
      .map((part) => '${part[0].toUpperCase()}${part.substring(1)}')
      .toList();

  if (parts.isEmpty) {
    return slug;
  }
  if (parts.length == 1) {
    return parts.first;
  }
  return parts.first;
}
