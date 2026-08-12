import 'package:codequest/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('AppColors.fromHex parses 6-digit hex', () {
    final color = AppColors.fromHex('#58CC02');
    expect(color, const Color(0xFF58CC02));
  });

  test('AppColors.fromHex falls back on invalid input', () {
    final color = AppColors.fromHex('not-a-color');
    expect(color, AppColors.primary);
  });

  testWidgets('theme builds a MaterialApp', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: buildTheme(),
        home: const Scaffold(body: Text('CodeQuest')),
      ),
    );
    expect(find.text('CodeQuest'), findsOneWidget);
  });
}
