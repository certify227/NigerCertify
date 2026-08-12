import 'package:flutter/material.dart';

import '../theme.dart';

/// A small pill showing an icon and a value (used for XP, streak, hearts).
class StatChip extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String value;

  const StatChip({
    super.key,
    required this.icon,
    required this.color,
    required this.value,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, color: color, size: 22),
        const SizedBox(width: 4),
        Text(
          value,
          style: const TextStyle(
            fontWeight: FontWeight.bold,
            fontSize: 16,
            color: AppColors.textDark,
          ),
        ),
      ],
    );
  }
}
