import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:itlingo/api_client.dart';
import 'package:itlingo/main.dart';

void main() {
  testWidgets('ITLingo app renders the home shell', (tester) async {
    final api = ItLingoApi(
      httpClient: MockClient((request) async => http.Response('[]', 200)),
    );

    await tester.pumpWidget(ItLingoApp(api: api));
    expect(find.text('ITLingo'), findsOneWidget);
  });
}
