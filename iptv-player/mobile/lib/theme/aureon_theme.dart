import 'package:flutter/material.dart';

const canvasDark = Color(0xFF0C0E12);
const panelDark = Color(0xFF14181F);
const panel2Dark = Color(0xFF1C222C);
const lineDark = Color(0xFF2C3442);
const inkDark = Color(0xFFF3EFE6);
const mutedDark = Color(0xFFA8A092);
const accent = Color(0xFFE2A13A);
const accentInk = Color(0xFF1C1408);

const canvasLight = Color(0xFFF4F0E8);
const panelLight = Color(0xFFFFFDF8);
const panel2Light = Color(0xFFEFE8DC);
const lineLight = Color(0xFFE0D6C6);
const inkLight = Color(0xFF1D1A16);
const mutedLight = Color(0xFF6F675C);
const accentLight = Color(0xFF9A640C);

ThemeData buildAureonTheme({required Brightness brightness}) {
  final dark = brightness == Brightness.dark;
  final canvas = dark ? canvasDark : canvasLight;
  final panel = dark ? panelDark : panelLight;
  final ink = dark ? inkDark : inkLight;
  final muted = dark ? mutedDark : mutedLight;
  final line = dark ? lineDark : lineLight;
  final accentColor = dark ? accent : accentLight;
  final onAccent = dark ? accentInk : canvasLight;

  final scheme = ColorScheme(
    brightness: brightness,
    primary: accentColor,
    onPrimary: onAccent,
    secondary: accentColor,
    onSecondary: onAccent,
    error: const Color(0xFFEF8B8B),
    onError: const Color(0xFF2A1010),
    surface: panel,
    onSurface: ink,
  );

  return ThemeData(
    useMaterial3: true,
    brightness: brightness,
    fontFamily: 'Outfit',
    colorScheme: scheme,
    scaffoldBackgroundColor: canvas,
    dividerColor: line,
    appBarTheme: AppBarTheme(
      backgroundColor: panel,
      foregroundColor: ink,
      elevation: 0,
      scrolledUnderElevation: 0,
      centerTitle: false,
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: panel,
      indicatorColor: accentColor.withValues(alpha: 0.22),
      labelTextStyle: WidgetStatePropertyAll(TextStyle(fontSize: 12, color: ink, fontFamily: 'Outfit')),
    ),
    navigationRailTheme: NavigationRailThemeData(
      backgroundColor: panel,
      indicatorColor: accentColor.withValues(alpha: 0.22),
      selectedIconTheme: IconThemeData(color: accentColor),
      unselectedIconTheme: IconThemeData(color: muted),
    ),
    cardTheme: CardThemeData(
      color: panel,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
        side: BorderSide(color: line),
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: accentColor,
        foregroundColor: onAccent,
        textStyle: const TextStyle(fontFamily: 'Outfit', fontWeight: FontWeight.w600),
      ),
    ),
  );
}
