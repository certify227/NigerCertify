import 'package:flutter_test/flutter_test.dart';
import 'package:itlingo/main.dart';

void main() {
  testWidgets('ITLingo app renders the home shell', (tester) async {
    await tester.pumpWidget(const ItLingoApp());
    expect(find.text('ITLingo'), findsOneWidget);
  });
}
