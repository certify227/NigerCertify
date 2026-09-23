import 'package:flutter/material.dart';

import '../theme/aureon_theme.dart';

class AureonMark extends StatelessWidget {
  const AureonMark({super.key, this.size = 36});

  final double size;

  @override
  Widget build(BuildContext context) {
    return CustomPaint(size: Size.square(size), painter: const _MarkPainter());
  }
}

class _MarkPainter extends CustomPainter {
  const _MarkPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final scale = size.width / 64;
    canvas.scale(scale);
    final frame = RRect.fromRectAndRadius(const Rect.fromLTWH(0, 0, 64, 64), const Radius.circular(18));
    canvas.drawRRect(frame, Paint()..color = accent);
    final screen = RRect.fromRectAndRadius(const Rect.fromLTWH(14, 16, 36, 26), const Radius.circular(6));
    canvas.drawRRect(screen, Paint()..color = accentInk);
    final play = Path()
      ..moveTo(28, 23.5)
      ..lineTo(28, 34.5)
      ..lineTo(37, 29)
      ..close();
    canvas.drawPath(play, Paint()..color = accent);
    final stand = RRect.fromRectAndRadius(const Rect.fromLTWH(22, 46, 20, 3), const Radius.circular(1.5));
    canvas.drawRRect(stand, Paint()..color = accentInk);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
