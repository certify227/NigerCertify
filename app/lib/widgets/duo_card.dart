import 'package:flutter/material.dart';

class DuoCard extends StatelessWidget {
  const DuoCard({
    super.key,
    required this.child,
    this.onTap,
    this.color,
  });

  final Widget child;
  final VoidCallback? onTap;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    return Card(
      color: color ?? Theme.of(context).colorScheme.surface,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(24),
        side: BorderSide(color: Theme.of(context).colorScheme.outlineVariant),
      ),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: child,
        ),
      ),
    );
  }
}

class XpPill extends StatelessWidget {
  const XpPill({super.key, required this.xp});

  final int xp;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: const Color(0xfffff3bf),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(
        '+$xp XP',
        style: Theme.of(context).textTheme.labelLarge?.copyWith(
              color: const Color(0xff8a5a00),
              fontWeight: FontWeight.w800,
            ),
      ),
    );
  }
}
