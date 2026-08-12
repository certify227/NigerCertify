import 'package:flutter/material.dart';

import '../models/models.dart';

class StatBar extends StatelessWidget {
  final Dashboard dashboard;

  const StatBar({super.key, required this.dashboard});

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        _Chip(icon: '🔥', value: '${dashboard.streak}'),
        const SizedBox(width: 6),
        _Chip(icon: '❤️', value: '${dashboard.hearts}'),
        const SizedBox(width: 6),
        _Chip(icon: '⚡', value: '${dashboard.xp}'),
      ],
    );
  }
}

class _Chip extends StatelessWidget {
  final String icon;
  final String value;

  const _Chip({required this.icon, required this.value});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: const Color(0xFFE5E5E5)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(icon, style: const TextStyle(fontSize: 14)),
          const SizedBox(width: 4),
          Text(value, style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 13)),
        ],
      ),
    );
  }
}
