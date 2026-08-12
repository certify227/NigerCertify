import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/models.dart';
import '../state/app_state.dart';
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
    _future = context.read<AppState>().api.leaderboard();
  }

  Future<void> _reload() async {
    setState(() {
      _future = context.read<AppState>().api.leaderboard();
    });
    await _future;
  }

  @override
  Widget build(BuildContext context) {
    final me = context.watch<AppState>().profile?.username;
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
              return Center(child: Text('Erreur : ${snapshot.error}'));
            }
            final entries = snapshot.data ?? [];
            if (entries.isEmpty) {
              return const Center(child: Text('Aucun joueur pour le moment.'));
            }
            return ListView.separated(
              padding: const EdgeInsets.all(16),
              itemCount: entries.length,
              separatorBuilder: (_, __) => const Divider(height: 1),
              itemBuilder: (context, i) {
                final e = entries[i];
                final isMe = e.username == me;
                return _LeaderboardRow(rank: i + 1, entry: e, isMe: isMe);
              },
            );
          },
        ),
      ),
    );
  }
}

class _LeaderboardRow extends StatelessWidget {
  final int rank;
  final LeaderboardEntry entry;
  final bool isMe;

  const _LeaderboardRow({
    required this.rank,
    required this.entry,
    required this.isMe,
  });

  Color get _medalColor {
    switch (rank) {
      case 1:
        return AppColors.gold;
      case 2:
        return const Color(0xFFB0B0B0);
      case 3:
        return const Color(0xFFCD7F32);
      default:
        return AppColors.muted;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: isMe
            ? AppColors.primary.withValues(alpha: 0.1)
            : Colors.transparent,
        borderRadius: BorderRadius.circular(12),
      ),
      child: ListTile(
        leading: SizedBox(
          width: 36,
          child: rank <= 3
              ? Icon(Icons.emoji_events, color: _medalColor)
              : Text(
                  '$rank',
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 16,
                    color: AppColors.muted,
                  ),
                ),
        ),
        title: Text(
          entry.username,
          style: TextStyle(
            fontWeight: isMe ? FontWeight.w800 : FontWeight.w600,
            color: AppColors.textDark,
          ),
        ),
        subtitle: Text('Niveau ${entry.level} · 🔥 ${entry.streak}'),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.bolt, color: AppColors.secondary, size: 20),
            const SizedBox(width: 4),
            Text(
              '${entry.xp}',
              style: const TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
