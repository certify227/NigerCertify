import 'package:flutter/material.dart';

enum AppTab { home, live, favorites, playlists, settings }

class TabSpec {
  const TabSpec({
    required this.tab,
    required this.shortLabel,
    required this.title,
    required this.icon,
    required this.selectedIcon,
  });

  final AppTab tab;
  final String shortLabel;
  final String title;
  final IconData icon;
  final IconData selectedIcon;
}

const appTabs = <TabSpec>[
  TabSpec(
    tab: AppTab.home,
    shortLabel: 'Accueil',
    title: 'Accueil',
    icon: Icons.home_outlined,
    selectedIcon: Icons.home,
  ),
  TabSpec(
    tab: AppTab.live,
    shortLabel: 'Direct',
    title: 'TV en direct',
    icon: Icons.live_tv_outlined,
    selectedIcon: Icons.live_tv,
  ),
  TabSpec(
    tab: AppTab.favorites,
    shortLabel: 'Favoris',
    title: 'Favoris',
    icon: Icons.favorite_border,
    selectedIcon: Icons.favorite,
  ),
  TabSpec(
    tab: AppTab.playlists,
    shortLabel: 'Listes',
    title: 'Playlists',
    icon: Icons.playlist_play_outlined,
    selectedIcon: Icons.playlist_play,
  ),
  TabSpec(
    tab: AppTab.settings,
    shortLabel: 'Réglages',
    title: 'Paramètres',
    icon: Icons.settings_outlined,
    selectedIcon: Icons.settings,
  ),
];
