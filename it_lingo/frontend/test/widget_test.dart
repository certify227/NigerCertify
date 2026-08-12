import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:it_lingo/main.dart';

void main() {
  testWidgets('renders fallback dashboard content', (WidgetTester tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: FallbackDashboardScreen(data: DashboardData.fallback()),
      ),
    );

    expect(find.text('ItLingo - maquette locale'), findsOneWidget);
    expect(find.text('Fondamentaux Python'), findsOneWidget);
    expect(find.text('Challenge du jour'), findsOneWidget);
  });
}
