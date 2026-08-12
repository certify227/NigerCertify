import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../widgets/duo_card.dart';
import 'track_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key, required this.api});

  final ItLingoApi api;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  late Future<List<Track>> _tracks;

  @override
  void initState() {
    super.initState();
    _tracks = widget.api.fetchTracks();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('ITLingo'),
        actions: const [
          Padding(
            padding: EdgeInsets.only(right: 16),
            child: Chip(label: Text('🔥 Série 0')),
          ),
        ],
      ),
      body: FutureBuilder<List<Track>>(
        future: _tracks,
        builder: (context, snapshot) {
          if (snapshot.connectionState != ConnectionState.done) {
            return const Center(child: CircularProgressIndicator());
          }
          if (snapshot.hasError) {
            return _ErrorState(
              message: snapshot.error.toString(),
              onRetry: () => setState(() => _tracks = widget.api.fetchTracks()),
            );
          }
          final tracks = snapshot.data ?? [];
          return ListView(
            padding: const EdgeInsets.all(20),
            children: [
              Text(
                'Apprends l’informatique en mini-défis',
                style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.w900),
              ),
              const SizedBox(height: 8),
              Text(
                'Choisis un parcours, gagne de l’XP et construis une routine quotidienne.',
                style: Theme.of(context).textTheme.bodyLarge,
              ),
              const SizedBox(height: 24),
              LayoutBuilder(
                builder: (context, constraints) {
                  final useGrid = constraints.maxWidth >= 720;
                  if (!useGrid) {
                    return Column(
                      children: tracks.map((track) => _TrackCard(api: widget.api, track: track)).toList(),
                    );
                  }
                  return GridView.count(
                    crossAxisCount: 2,
                    childAspectRatio: 1.8,
                    mainAxisSpacing: 16,
                    crossAxisSpacing: 16,
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    children: tracks.map((track) => _TrackCard(api: widget.api, track: track)).toList(),
                  );
                },
              ),
            ],
          );
        },
      ),
    );
  }
}

class _TrackCard extends StatelessWidget {
  const _TrackCard({required this.api, required this.track});

  final ItLingoApi api;
  final Track track;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: DuoCard(
        onTap: () {
          Navigator.of(context).push(
            MaterialPageRoute(builder: (_) => TrackScreen(api: api, track: track)),
          );
        },
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                CircleAvatar(
                  backgroundColor: Color(int.parse(track.color.replaceFirst('#', '0xff'))),
                  child: const Icon(Icons.terminal, color: Colors.white),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(track.title, style: Theme.of(context).textTheme.titleLarge),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Text(track.description),
            const SizedBox(height: 16),
            Text('${track.units.length} unité(s)', style: Theme.of(context).textTheme.labelLarge),
          ],
        ),
      ),
    );
  }
}

class _ErrorState extends StatelessWidget {
  const _ErrorState({required this.message, required this.onRetry});

  final String message;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.cloud_off, size: 48),
            const SizedBox(height: 12),
            Text('Impossible de charger les parcours.', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(message, textAlign: TextAlign.center),
            const SizedBox(height: 16),
            FilledButton(onPressed: onRetry, child: const Text('Réessayer')),
          ],
        ),
      ),
    );
  }
}
