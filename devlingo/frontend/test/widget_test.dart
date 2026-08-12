import 'package:devlingo_app/app.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('renders the learning dashboard', (WidgetTester tester) async {
    await tester.pumpWidget(DevLingoApp(repository: FakeLearningRepository()));
    await tester.pumpAndSettle();

    expect(find.text('DevLingo'), findsOneWidget);
    expect(find.text('Votre parcours du jour'), findsOneWidget);
    expect(find.text('Python'), findsOneWidget);
    expect(find.text('Variables et types'), findsOneWidget);
  });
}

class FakeLearningRepository implements LearningRepository {
  @override
  Future<DashboardData> fetchDashboard() async {
    return DashboardData(
      profile: LearnerProfile(
        displayName: 'Aicha',
        targetRole: 'Developpeuse mobile et cloud',
        dailyGoalMinutes: 20,
        streakDays: 6,
        totalXp: 220,
        hearts: 5,
      ),
      dailyPlan: DailyPlan(
        goalMinutes: 20,
        recommendedFocus: 'Python, Git et Linux',
        callToAction: 'Lancer la prochaine lecon',
      ),
      tracks: [
        TrackData(
          title: 'Python',
          description: 'Variables, fonctions et automatisation.',
          colorStart: '#2563EB',
          colorEnd: '#7C3AED',
          completedLessons: 1,
          totalLessons: 2,
          progressPercent: 50,
          lessons: [
            LessonPreview(
              title: 'Variables et types',
              slug: 'python-variables',
              estimatedMinutes: 7,
              xpReward: 15,
              status: 'completed',
            ),
            LessonPreview(
              title: 'Boucles',
              slug: 'python-boucles',
              estimatedMinutes: 8,
              xpReward: 18,
              status: 'available',
            ),
          ],
        ),
      ],
    );
  }

  @override
  Future<LessonDetail> fetchLesson(String slug) async {
    return LessonDetail(
      title: 'Variables et types',
      summary: 'Manipuler des chaines, entiers et listes.',
      trackTitle: 'Python',
      estimatedMinutes: 7,
      xpReward: 15,
      challengeCount: 2,
      exercises: [
        ExerciseItem(
          prompt: 'Quel type renvoie len([1, 2, 3]) ?',
          options: ['str', 'int', 'list'],
          correctAnswer: 'int',
          explanation: 'len renvoie toujours un entier.',
          sortOrder: 1,
        ),
      ],
    );
  }
}
