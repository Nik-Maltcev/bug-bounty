import { useState, useEffect } from 'react';
import { ProviderType, type LLMSettings } from '../../types/ai';
import { getLLMSettings, updateLLMSettings, testLLMConnection } from '../../services/aiApi';

const CLOUD_PROVIDERS = [ProviderType.DEEPSEEK, ProviderType.OPENAI, ProviderType.ANTHROPIC];

export default function LLMSettingsForm() {
  const [settings, setSettings] = useState<LLMSettings>({
    provider: ProviderType.DEEPSEEK,
    base_url: 'https://api.deepseek.com',
    model: 'deepseek-v4-flash',
    max_tokens: 4096,
    temperature: 0.3,
    is_connected: false,
  });
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState('');

  useEffect(() => {
    getLLMSettings().then(setSettings).catch(() => {});
  }, []);

  const isCloud = CLOUD_PROVIDERS.includes(settings.provider as ProviderType);

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateLLMSettings(settings);
      setStatus('Settings saved');
    } catch {
      setStatus('Failed to save');
    }
    setSaving(false);
  };

  const handleTest = async () => {
    setTesting(true);
    try {
      const result = await testLLMConnection();
      setStatus(result.connected ? 'Connected!' : `Not connected: ${result.error || 'unknown'}`);
    } catch {
      setStatus('Connection test failed');
    }
    setTesting(false);
  };

  return (
    <div style={{ maxWidth: '500px', padding: '16px' }}>
      <h3>LLM Provider Settings</h3>

      {isCloud && (
        <div style={{ padding: '10px', background: '#fff3cd', borderRadius: '8px', marginBottom: '16px', fontSize: '13px' }}>
          ⚠️ Cloud provider selected. Data will be sent to an external service.
        </div>
      )}

      <label style={{ display: 'block', marginBottom: '12px' }}>
        Provider
        <select
          value={settings.provider}
          onChange={(e) => setSettings({ ...settings, provider: e.target.value })}
          style={{ display: 'block', width: '100%', padding: '8px', marginTop: '4px' }}
        >
          {Object.values(ProviderType).map((p) => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
      </label>

      <label style={{ display: 'block', marginBottom: '12px' }}>
        Base URL
        <input
          value={settings.base_url}
          onChange={(e) => setSettings({ ...settings, base_url: e.target.value })}
          style={{ display: 'block', width: '100%', padding: '8px', marginTop: '4px' }}
        />
      </label>

      <label style={{ display: 'block', marginBottom: '12px' }}>
        Model
        <input
          value={settings.model}
          onChange={(e) => setSettings({ ...settings, model: e.target.value })}
          style={{ display: 'block', width: '100%', padding: '8px', marginTop: '4px' }}
        />
      </label>

      <label style={{ display: 'block', marginBottom: '12px' }}>
        API Key
        <input
          type="password"
          value={settings.api_key || ''}
          onChange={(e) => setSettings({ ...settings, api_key: e.target.value })}
          placeholder="sk-..."
          style={{ display: 'block', width: '100%', padding: '8px', marginTop: '4px' }}
        />
      </label>

      <label style={{ display: 'block', marginBottom: '12px' }}>
        Temperature: {settings.temperature}
        <input
          type="range"
          min="0"
          max="2"
          step="0.1"
          value={settings.temperature}
          onChange={(e) => setSettings({ ...settings, temperature: parseFloat(e.target.value) })}
          style={{ display: 'block', width: '100%', marginTop: '4px' }}
        />
      </label>

      <label style={{ display: 'block', marginBottom: '16px' }}>
        Max Tokens
        <input
          type="number"
          min={256}
          max={32768}
          value={settings.max_tokens}
          onChange={(e) => setSettings({ ...settings, max_tokens: parseInt(e.target.value) || 4096 })}
          style={{ display: 'block', width: '100%', padding: '8px', marginTop: '4px' }}
        />
      </label>

      <div style={{ display: 'flex', gap: '8px' }}>
        <button onClick={handleSave} disabled={saving} style={{ padding: '8px 20px' }}>
          {saving ? 'Saving...' : 'Save'}
        </button>
        <button onClick={handleTest} disabled={testing} style={{ padding: '8px 20px' }}>
          {testing ? 'Testing...' : 'Test Connection'}
        </button>
      </div>

      {status && <div style={{ marginTop: '12px', fontSize: '13px', color: '#555' }}>{status}</div>}
    </div>
  );
}
