import 'package:flutter_test/flutter_test.dart';
import 'package:codequest/main.dart';

void main() {
  testWidgets('CodeQuest app smoke test', (WidgetTester tester) async {
    await tester.pumpWidget(const CodeQuestApp());
    expect(find.text('CodeQuest'), findsOneWidget);
  });
}
