import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../app_state.dart';
import '../models.dart';
import '../theme.dart';

class LeaderboardScreen extends StatefulWidget {
  const LeaderboardScreen({super.key});

  @override
  State<LeaderboardScreen> createState() => _LeaderboardScreenState();
}

class _LeaderboardScreenState extends State<LeaderboardScreen> {
  late Future<List<LeaderboardEntry>> _future;

  @override
  void initState() {
    super.initState();
    _future = context.read<AppState>().api.fetchLeaderboard();
  }

  Future<void> _reload() async {
    setState(() {
      _future = context.read<AppState>().api.fetchLeaderboard();
    });
  }

  @override
  Widget build(BuildContext context) {
    final me = context.watch<AppState>().user;
    return Scaffold(
      appBar: AppBar(title: const Text('Classement')),
      body: RefreshIndicator(
        onRefresh: _reload,
        child: FutureBuilder<List<LeaderboardEntry>>(
          future: _future,
          builder: (context, snapshot) {
            if (snapshot.connectionState == ConnectionState.waiting) {
              return const Center(child: CircularProgressIndicator());
            }
            if (snapshot.hasError) {
              return Center(child: Text('${snapshot.error}'));
            }
            final entries = snapshot.data ?? [];
            if (entries.isEmpty) {
              return const Center(child: Text('Aucun joueur pour le moment.'));
            }
            return ListView.separated(
              padding: const EdgeInsets.all(16),
              itemCount: entries.length,
              separatorBuilder: (_, _) => const Divider(height: 1),
              itemBuilder: (context, i) {
                final e = entries[i];
                final isMe = me != null && e.username == me.username;
                return Container(
                  color: isMe
                      ? AppColors.primary.withValues(alpha: 0.08)
                      : null,
                  child: ListTile(
                    leading: _rankBadge(e.rank),
                    title: Row(
                      children: [
                        Text(e.avatar, style: const TextStyle(fontSize: 20)),
                        const SizedBox(width: 8),
                        Text(
                          e.username,
                          style: TextStyle(
                            fontWeight:
                                isMe ? FontWeight.bold : FontWeight.w500,
                          ),
                        ),
                      ],
                    ),
                    subtitle: Text('🔥 ${e.streakCount} jours'),
                    trailing: Text(
                      '${e.xp} XP',
                      style: const TextStyle(
                        fontWeight: FontWeight.bold,
                        color: AppColors.primary,
                      ),
                    ),
                  ),
                );
              },
            );
          },
        ),
      ),
    );
  }

  Widget _rankBadge(int rank) {
    final medals = {1: '🥇', 2: '🥈', 3: '🥉'};
    if (medals.containsKey(rank)) {
      return Text(medals[rank]!, style: const TextStyle(fontSize: 24));
    }
    return CircleAvatar(
      radius: 16,
      backgroundColor: AppColors.locked,
      child: Text(
        '$rank',
        style: const TextStyle(
          color: AppColors.textDark,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}
