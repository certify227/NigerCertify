import 'package:flutter_test/flutter_test.dart';
import 'package:itquest/main.dart';

void main() {
  test('Track parses nested lessons from API payload', () {
    final track = Track.fromJson({
      'id': 1,
      'title': 'Python debutant',
      'description': 'Bases Python',
      'icon': 'terminal',
      'lessons': [
        {
          'id': 10,
          'title': 'Variables',
          'summary': 'Comprendre les variables',
          'xp_reward': 20,
        },
      ],
    });

    expect(track.title, 'Python debutant');
    expect(track.lessons, hasLength(1));
    expect(track.lessons.first.xpReward, 20);
  });
}
