import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../providers/app_state.dart';
import '../theme/app_theme.dart';
import 'login_screen.dart';

class ProfileScreen extends StatefulWidget {
  const ProfileScreen({super.key});

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  bool _savingReminder = false;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final user = state.user;
    final dashboard = state.dashboard;

    if (user == null) return const Center(child: CircularProgressIndicator());

    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        children: [
          CircleAvatar(
            radius: 48,
            backgroundColor: AppTheme.primaryGreen,
            child: Text(
              user.username[0].toUpperCase(),
              style: const TextStyle(fontSize: 36, color: Colors.white, fontWeight: FontWeight.w900),
            ),
          ),
          const SizedBox(height: 12),
          Text(user.username, style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w900)),
          Text('Niveau ${user.level}', style: const TextStyle(color: AppTheme.textMuted)),
          const SizedBox(height: 24),
          _StatRow(label: 'XP total', value: '${user.xp}', icon: '⚡'),
          _StatRow(label: 'Série', value: '${user.streak} jours', icon: '🔥'),
          _StatRow(label: 'Cœurs', value: '${user.hearts}', icon: '❤️'),
          if (dashboard != null) ...[
            _StatRow(label: 'XP aujourd\'hui', value: '${dashboard.xpToday}', icon: '📈'),
            _StatRow(label: 'Leçons du jour', value: '${dashboard.lessonsCompletedToday}', icon: '📚'),
          ],
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: const Color(0xFFE5E5E5)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('🔔 Rappel de série', style: TextStyle(fontWeight: FontWeight.w800, fontSize: 16)),
                const SizedBox(height: 4),
                const Text(
                  'Recevez une notification quotidienne pour ne pas perdre votre série.',
                  style: TextStyle(color: AppTheme.textMuted, fontSize: 13),
                ),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('Activer le rappel'),
                  value: user.reminderEnabled,
                  activeColor: AppTheme.primaryGreen,
                  onChanged: _savingReminder || state.isOffline
                      ? null
                      : (v) async {
                          setState(() => _savingReminder = true);
                          try {
                            await context.read<AppState>().updateReminders(
                                  enabled: v,
                                  hour: user.reminderHour,
                                );
                          } finally {
                            if (mounted) setState(() => _savingReminder = false);
                          }
                        },
                ),
                if (user.reminderEnabled) ...[
                  const Text('Heure du rappel', style: TextStyle(fontWeight: FontWeight.w600)),
                  Slider(
                    value: user.reminderHour.toDouble(),
                    min: 6,
                    max: 22,
                    divisions: 16,
                    label: '${user.reminderHour}h00',
                    activeColor: AppTheme.primaryGreen,
                    onChanged: _savingReminder || state.isOffline
                        ? null
                        : (v) async {
                            setState(() => _savingReminder = true);
                            try {
                              await context.read<AppState>().updateReminders(
                                    enabled: true,
                                    hour: v.round(),
                                  );
                            } finally {
                              if (mounted) setState(() => _savingReminder = false);
                            }
                          },
                  ),
                ],
              ],
            ),
          ),
          const SizedBox(height: 32),
          OutlinedButton.icon(
            onPressed: () async {
              await context.read<AppState>().logout();
              if (!context.mounted) return;
              Navigator.of(context).pushAndRemoveUntil(
                MaterialPageRoute(builder: (_) => const LoginScreen()),
                (_) => false,
              );
            },
            icon: const Icon(Icons.logout),
            label: const Text('Se déconnecter'),
          ),
        ],
      ),
    );
  }
}

class _StatRow extends StatelessWidget {
  final String label;
  final String value;
  final String icon;

  const _StatRow({required this.label, required this.value, required this.icon});

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFFE5E5E5)),
      ),
      child: Row(
        children: [
          Text(icon, style: const TextStyle(fontSize: 22)),
          const SizedBox(width: 12),
          Expanded(child: Text(label, style: const TextStyle(fontWeight: FontWeight.w600))),
          Text(value, style: const TextStyle(fontWeight: FontWeight.w800, color: AppTheme.primaryGreen)),
        ],
      ),
    );
  }
}
