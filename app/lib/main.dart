import 'package:flutter/material.dart';

import 'api_client.dart';
import 'screens/home_screen.dart';

void main() {
  runApp(const ItLingoApp());
}

class ItLingoApp extends StatelessWidget {
  const ItLingoApp({super.key, this.api});

  final ItLingoApi? api;

  @override
  Widget build(BuildContext context) {
    final colorScheme = ColorScheme.fromSeed(
      seedColor: const Color(0xff58cc02),
      brightness: Brightness.light,
    );
    return MaterialApp(
      title: 'ITLingo',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: colorScheme,
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xfff7f8fb),
        appBarTheme: const AppBarTheme(centerTitle: false),
        filledButtonTheme: FilledButtonThemeData(
          style: FilledButton.styleFrom(
            minimumSize: const Size.fromHeight(52),
            textStyle: const TextStyle(fontWeight: FontWeight.w800),
          ),
        ),
      ),
      home: HomeScreen(api: api ?? ItLingoApi()),
    );
  }
}
