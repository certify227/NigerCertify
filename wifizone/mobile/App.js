import { useState } from 'react';
import {
  ActivityIndicator,
  Button,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

const API_BASE = process.env.EXPO_PUBLIC_API_URL || 'http://localhost:8080/api/v1';

export default function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState(null);
  const [live, setLive] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function login() {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/auth/token/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Connexion échouée');
      setToken(data.access);
      await AsyncStorage.setItem('jwt', data.access);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function fetchLive() {
    if (!token) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/dashboard/live/`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error('Erreur API');
      setLive(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.inner}>
        <Text style={styles.title}>WiFiZone Pro Mobile</Text>
        {!token ? (
          <View>
            <TextInput
              style={styles.input}
              placeholder="Identifiant"
              value={username}
              onChangeText={setUsername}
              autoCapitalize="none"
            />
            <TextInput
              style={styles.input}
              placeholder="Mot de passe"
              value={password}
              onChangeText={setPassword}
              secureTextEntry
            />
            <Button title="Connexion JWT" onPress={login} />
          </View>
        ) : (
          <View>
            <Button title="Stats live" onPress={fetchLive} />
            <Button title="Déconnexion" onPress={() => setToken(null)} />
            {live && (
              <View style={styles.card}>
                <Text>Routeurs : {live.router_count}</Text>
                <Text>En ligne : {live.online_count}</Text>
                <Text>Vouchers : {live.total_vouchers}</Text>
                <Text>Revenus : {live.revenue} FCFA</Text>
              </View>
            )}
          </View>
        )}
        {loading && <ActivityIndicator style={{ marginTop: 16 }} />}
        {error ? <Text style={styles.error}>{error}</Text> : null}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#1a1d23' },
  inner: { padding: 20 },
  title: { color: '#fff', fontSize: 22, marginBottom: 20, fontWeight: '700' },
  input: {
    backgroundColor: '#fff',
    borderRadius: 8,
    padding: 12,
    marginBottom: 12,
  },
  card: {
    backgroundColor: '#2d323c',
    padding: 16,
    borderRadius: 8,
    marginTop: 16,
    color: '#fff',
  },
  error: { color: '#ff6b6b', marginTop: 12 },
});
