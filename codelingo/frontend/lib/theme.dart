import 'package:flutter/material.dart';

/// CodeLingo palette, inspired by playful language-learning apps.
class AppColors {
  static const Color primary = Color(0xFF58CC02); // Duolingo-ish green
  static const Color primaryDark = Color(0xFF46A302);
  static const Color secondary = Color(0xFF1CB0F6);
  static const Color danger = Color(0xFFFF4B4B);
  static const Color gold = Color(0xFFFFC800);
  static const Color purple = Color(0xFFCE82FF);
  static const Color background = Color(0xFFF7F7F7);
  static const Color card = Colors.white;
  static const Color textDark = Color(0xFF3C3C3C);
  static const Color textLight = Color(0xFF777777);
  static const Color locked = Color(0xFFE5E5E5);
}

Color hexToColor(String hex) {
  var h = hex.replaceAll('#', '');
  if (h.length == 6) h = 'FF$h';
  return Color(int.parse(h, radix: 16));
}

ThemeData buildTheme() {
  final base = ThemeData(
    useMaterial3: true,
    colorScheme: ColorScheme.fromSeed(
      seedColor: AppColors.primary,
      primary: AppColors.primary,
    ),
    scaffoldBackgroundColor: AppColors.background,
    fontFamily: 'Roboto',
  );
  return base.copyWith(
    appBarTheme: const AppBarTheme(
      backgroundColor: Colors.white,
      foregroundColor: AppColors.textDark,
      elevation: 0,
      centerTitle: true,
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        backgroundColor: AppColors.primary,
        foregroundColor: Colors.white,
        elevation: 0,
        padding: const EdgeInsets.symmetric(vertical: 16),
        textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
        ),
      ),
    ),
  );
}
