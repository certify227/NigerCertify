import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/models.dart';
import '../providers/app_state.dart';
import '../theme/app_theme.dart';
import '../widgets/stat_bar.dart';
import '../widgets/track_card.dart';
import 'leaderboard_screen.dart';
import 'profile_screen.dart';
import 'track_detail_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _tabIndex = 0;

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, state, _) {
        final dashboard = state.dashboard;
        return Scaffold(
          appBar: AppBar(
            title: Text(_tabIndex == 0 ? 'Parcours' : _tabIndex == 1 ? 'Classement' : 'Profil'),
            actions: [
              if (dashboard != null) StatBar(dashboard: dashboard),
              const SizedBox(width: 8),
            ],
          ),
          body: IndexedStack(
            index: _tabIndex,
            children: [
              _TracksTab(tracks: state.tracks),
              const LeaderboardScreen(),
              const ProfileScreen(),
            ],
          ),
          bottomNavigationBar: NavigationBar(
            selectedIndex: _tabIndex,
            onDestinationSelected: (i) => setState(() => _tabIndex = i),
            destinations: const [
              NavigationDestination(icon: Icon(Icons.school_outlined), selectedIcon: Icon(Icons.school), label: 'Apprendre'),
              NavigationDestination(icon: Icon(Icons.leaderboard_outlined), selectedIcon: Icon(Icons.leaderboard), label: 'Classement'),
              NavigationDestination(icon: Icon(Icons.person_outline), selectedIcon: Icon(Icons.person), label: 'Profil'),
            ],
          ),
        );
      },
    );
  }
}

class _TracksTab extends StatelessWidget {
  final List<Track> tracks;

  const _TracksTab({required this.tracks});

  @override
  Widget build(BuildContext context) {
    if (tracks.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    return RefreshIndicator(
      onRefresh: () => context.read<AppState>().refresh(),
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(
            'Choisissez un parcours',
            style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 4),
          Text(
            'Python, réseaux, cybersécurité et plus encore',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: AppTheme.textMuted),
          ),
          const SizedBox(height: 20),
          ...tracks.map((track) => Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: TrackCard(
                  track: track,
                  onTap: () => Navigator.of(context).push(
                    MaterialPageRoute(
                      builder: (_) => TrackDetailScreen(slug: track.slug, title: track.title),
                    ),
                  ),
                ),
              )),
        ],
      ),
    );
  }
}
