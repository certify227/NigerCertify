import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:codelingo/theme.dart';

void main() {
  test('hexToColor parses 6-digit hex with implicit alpha', () {
    final color = hexToColor('#58CC02');
    expect(color.toARGB32(), 0xFF58CC02);
  });

  test('hexToColor keeps provided alpha', () {
    final color = hexToColor('8058CC02');
    expect(color.toARGB32(), 0x8058CC02);
  });

  testWidgets('theme builds without error', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: buildTheme(),
        home: const Scaffold(body: Text('CodeLingo')),
      ),
    );
    expect(find.text('CodeLingo'), findsOneWidget);
  });
}
