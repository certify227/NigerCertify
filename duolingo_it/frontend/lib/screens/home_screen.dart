import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../api/endpoints.dart';
import '../models/course.dart';
import '../models/user.dart';
import '../state/auth_state.dart';
import '../theme/app_theme.dart';
import '../widgets/stats_bar.dart';
import 'course_detail_screen.dart';
import 'login_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _index = 0;

  @override
  Widget build(BuildContext context) {
    final screens = [
      const _CoursesTab(),
      const _LeaderboardTab(),
      const _ProfileTab(),
    ];
    return Scaffold(
      appBar: AppBar(
        title: const Text('CodeLingo'),
        actions: [
          IconButton(
            tooltip: 'Actualiser',
            icon: const Icon(Icons.refresh),
            onPressed: () => context.read<AuthState>().refreshUser(),
          ),
        ],
      ),
      body: Column(
        children: [
          const StatsBar(),
          const Divider(height: 1),
          Expanded(child: screens[_index]),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _index,
        onDestinationSelected: (i) => setState(() => _index = i),
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.school_outlined),
            selectedIcon: Icon(Icons.school),
            label: 'Cours',
          ),
          NavigationDestination(
            icon: Icon(Icons.emoji_events_outlined),
            selectedIcon: Icon(Icons.emoji_events),
            label: 'Classement',
          ),
          NavigationDestination(
            icon: Icon(Icons.person_outline),
            selectedIcon: Icon(Icons.person),
            label: 'Profil',
          ),
        ],
      ),
    );
  }
}

class _CoursesTab extends StatefulWidget {
  const _CoursesTab();

  @override
  State<_CoursesTab> createState() => _CoursesTabState();
}

class _CoursesTabState extends State<_CoursesTab> {
  late Future<List<Course>> _future;

  @override
  void initState() {
    super.initState();
    _future = _load();
  }

  Future<List<Course>> _load() =>
      CoursesApi(context.read<AuthState>().client).list();

  Future<void> _refresh() async {
    setState(() => _future = _load());
    await _future;
  }

  @override
  Widget build(BuildContext context) {
    return RefreshIndicator(
      onRefresh: _refresh,
      child: FutureBuilder<List<Course>>(
        future: _future,
        builder: (context, snap) {
          if (snap.connectionState != ConnectionState.done) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snap.hasError) {
            return ListView(children: [
              const SizedBox(height: 80),
              Icon(Icons.wifi_off, size: 48, color: AppColors.textSecondary),
              const SizedBox(height: 12),
              Center(child: Text('Impossible de charger : ${snap.error}')),
            ]);
          }
          final courses = snap.data ?? const <Course>[];
          if (courses.isEmpty) {
            return const Center(child: Text('Aucun cours pour le moment.'));
          }
          return ListView.separated(
            padding: const EdgeInsets.all(16),
            itemCount: courses.length,
            separatorBuilder: (_, __) => const SizedBox(height: 12),
            itemBuilder: (context, i) => _CourseTile(course: courses[i]),
          );
        },
      ),
    );
  }
}

class _CourseTile extends StatelessWidget {
  const _CourseTile({required this.course});
  final Course course;

  @override
  Widget build(BuildContext context) {
    final color = _hexToColor(course.color);
    return Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: () {
          Navigator.of(context).push(MaterialPageRoute(
            builder: (_) => CourseDetailScreen(slug: course.slug),
          ));
        },
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              Container(
                width: 56,
                height: 56,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: color.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(course.icon, style: const TextStyle(fontSize: 28)),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      course.title,
                      style: const TextStyle(
                          fontSize: 18, fontWeight: FontWeight.w800),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      course.description,
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(color: AppColors.textSecondary),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      '${course.moduleCount} modules · ${course.lessonCount} leçons',
                      style: const TextStyle(
                        fontSize: 12,
                        color: AppColors.textSecondary,
                      ),
                    ),
                  ],
                ),
              ),
              const Icon(Icons.chevron_right, color: AppColors.textSecondary),
            ],
          ),
        ),
      ),
    );
  }
}

Color _hexToColor(String hex) {
  final cleaned = hex.replaceAll('#', '');
  final value = int.tryParse('FF$cleaned', radix: 16) ?? 0xFF58CC02;
  return Color(value);
}

class _LeaderboardTab extends StatefulWidget {
  const _LeaderboardTab();
  @override
  State<_LeaderboardTab> createState() => _LeaderboardTabState();
}

class _LeaderboardTabState extends State<_LeaderboardTab> {
  late Future<List<AppUser>> _future;

  @override
  void initState() {
    super.initState();
    _future = AuthApi(context.read<AuthState>().client).leaderboard();
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<List<AppUser>>(
      future: _future,
      builder: (context, snap) {
        if (snap.connectionState != ConnectionState.done) {
          return const Center(child: CircularProgressIndicator());
        }
        final data = snap.data ?? const <AppUser>[];
        return ListView.separated(
          padding: const EdgeInsets.all(16),
          separatorBuilder: (_, __) => const Divider(height: 1),
          itemCount: data.length,
          itemBuilder: (context, i) {
            final u = data[i];
            return ListTile(
              leading: CircleAvatar(
                backgroundColor: AppColors.primary,
                child: Text(
                  '${i + 1}',
                  style: const TextStyle(
                      color: Colors.white, fontWeight: FontWeight.w800),
                ),
              ),
              title: Text(u.username,
                  style: const TextStyle(fontWeight: FontWeight.w700)),
              subtitle: Text('Niveau ${u.level}'),
              trailing: Text('${u.xp} XP',
                  style: const TextStyle(
                      color: AppColors.secondary, fontWeight: FontWeight.w800)),
            );
          },
        );
      },
    );
  }
}

class _ProfileTab extends StatelessWidget {
  const _ProfileTab();

  @override
  Widget build(BuildContext context) {
    final user = context.watch<AuthState>().user;
    if (user == null) return const SizedBox.shrink();
    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        Center(
          child: CircleAvatar(
            radius: 48,
            backgroundColor: AppColors.primary,
            child: Text(
              user.username.isNotEmpty
                  ? user.username[0].toUpperCase()
                  : '?',
              style: const TextStyle(
                fontSize: 40,
                fontWeight: FontWeight.w900,
                color: Colors.white,
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        Center(
          child: Text(
            user.firstName.isNotEmpty ? user.firstName : user.username,
            style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w800),
          ),
        ),
        Center(
          child: Text(
            '@${user.username} · Niveau ${user.level}',
            style: const TextStyle(color: AppColors.textSecondary),
          ),
        ),
        const SizedBox(height: 24),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                Expanded(
                    child: _ProfileStat(
                        label: 'XP', value: '${user.xp}', color: AppColors.secondary)),
                Expanded(
                    child: _ProfileStat(
                        label: 'Série', value: '${user.streak}', color: AppColors.streak)),
                Expanded(
                    child: _ProfileStat(
                        label: 'Cœurs', value: '${user.hearts}', color: AppColors.heart)),
              ],
            ),
          ),
        ),
        const SizedBox(height: 24),
        OutlinedButton.icon(
          onPressed: () async {
            await context.read<AuthState>().logout();
            if (context.mounted) {
              Navigator.of(context).pushAndRemoveUntil(
                MaterialPageRoute(builder: (_) => const LoginScreen()),
                (route) => false,
              );
            }
          },
          icon: const Icon(Icons.logout),
          label: const Text('SE DÉCONNECTER'),
        ),
      ],
    );
  }
}

class _ProfileStat extends StatelessWidget {
  const _ProfileStat({required this.label, required this.value, required this.color});
  final String label;
  final String value;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text(value,
            style: TextStyle(
                fontSize: 22, fontWeight: FontWeight.w900, color: color)),
        Text(label, style: const TextStyle(color: AppColors.textSecondary)),
      ],
    );
  }
}
