import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../app_state.dart';
import '../theme.dart';

/// Top bar showing streak, gems, hearts — like the Duolingo header.
class StatsBar extends StatelessWidget implements PreferredSizeWidget {
  const StatsBar({super.key});

  @override
  Size get preferredSize => const Size.fromHeight(56);

  @override
  Widget build(BuildContext context) {
    final user = context.watch<AppState>().user;
    return AppBar(
      automaticallyImplyLeading: false,
      title: Row(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: [
          _stat('🔥', '${user?.streakCount ?? 0}', AppColors.gold),
          _stat('💎', '${user?.gems ?? 0}', AppColors.secondary),
          _stat('❤️', '${user?.hearts ?? 0}', AppColors.danger),
          _stat('⚡', '${user?.xp ?? 0}', AppColors.primary),
        ],
      ),
    );
  }

  Widget _stat(String emoji, String value, Color color) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(emoji, style: const TextStyle(fontSize: 18)),
        const SizedBox(width: 4),
        Text(
          value,
          style: TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: color,
          ),
        ),
      ],
    );
  }
}
