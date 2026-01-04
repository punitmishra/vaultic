//! AI-powered password management assistance
//!
//! Provides intelligent suggestions for:
//! - Password rotation
//! - Weak password detection
//! - Duplicate password detection
//! - Organization suggestions
//! - Breach checking
//!
//! Supports both local (Ollama/llama.cpp) and cloud (encrypted) backends.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::PasswordAnalyzer;
use crate::models::{
    AiSuggestion, PasswordStrength, SuggestionPriority, SuggestionType, VaultEntry,
};

/// AI module errors
#[derive(Debug, Error)]
pub enum AiError {
    #[error("AI backend unavailable: {0}")]
    BackendUnavailable(String),

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),
}

pub type AiResult<T> = Result<T, AiError>;

/// AI backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AiBackend {
    /// Local Ollama instance
    Ollama { url: String, model: String },
    /// Local llama.cpp server
    LlamaCpp { url: String, model_path: String },
    /// Disabled (only rule-based analysis)
    Disabled,
}

impl Default for AiBackend {
    fn default() -> Self {
        Self::Ollama {
            url: "http://localhost:11434".to_string(),
            model: "llama3.2:3b".to_string(),
        }
    }
}

/// Configuration for AI analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    pub backend: AiBackend,
    /// Days before password should be rotated
    pub rotation_threshold_days: u32,
    /// Minimum acceptable password strength
    pub min_password_strength: PasswordStrength,
    /// Check for breached passwords (Have I Been Pwned)
    pub check_breaches: bool,
    /// Enable smart suggestions
    pub enable_suggestions: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            backend: AiBackend::default(),
            rotation_threshold_days: 90,
            min_password_strength: PasswordStrength::Fair,
            check_breaches: true,
            enable_suggestions: true,
        }
    }
}

/// AI-powered password analyzer
pub struct PasswordAi {
    config: AiConfig,
    client: reqwest::Client,
}

impl PasswordAi {
    pub fn new(config: AiConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Analyze all entries and generate suggestions
    pub async fn analyze_vault(&self, entries: &[VaultEntry]) -> Vec<AiSuggestion> {
        let mut suggestions = Vec::new();

        // Rule-based analysis (always runs)
        suggestions.extend(self.check_weak_passwords(entries));
        suggestions.extend(self.check_duplicates(entries));
        suggestions.extend(self.check_rotation_needed(entries));
        suggestions.extend(self.check_unused_entries(entries));

        // AI-powered analysis (if enabled)
        if self.config.enable_suggestions {
            if let Ok(ai_suggestions) = self.get_ai_suggestions(entries).await {
                suggestions.extend(ai_suggestions);
            }
        }

        // Sort by priority
        suggestions.sort_by(|a, b| b.priority.cmp(&a.priority));
        suggestions
    }

    /// Check for weak passwords
    fn check_weak_passwords(&self, entries: &[VaultEntry]) -> Vec<AiSuggestion> {
        entries
            .iter()
            .filter_map(|entry| {
                if let Some(ref password) = entry.password {
                    let strength = PasswordAnalyzer::strength(password.expose());
                    if strength < self.config.min_password_strength {
                        return Some(AiSuggestion {
                            id: Uuid::new_v4(),
                            entry_id: Some(entry.id),
                            suggestion_type: SuggestionType::WeakPassword,
                            message: format!(
                                "'{}' has a {} password. Consider using a stronger password.",
                                entry.name,
                                format!("{:?}", strength).to_lowercase()
                            ),
                            priority: match strength {
                                PasswordStrength::VeryWeak => SuggestionPriority::Critical,
                                PasswordStrength::Weak => SuggestionPriority::High,
                                _ => SuggestionPriority::Medium,
                            },
                            created_at: Utc::now(),
                            dismissed: false,
                            action_taken: false,
                        });
                    }
                }
                None
            })
            .collect()
    }

    /// Check for duplicate passwords
    fn check_duplicates(&self, entries: &[VaultEntry]) -> Vec<AiSuggestion> {
        let mut password_hashes: HashMap<String, Vec<&VaultEntry>> = HashMap::new();

        for entry in entries {
            if let Some(ref password) = entry.password {
                let hash = Self::hash_password(password.expose());
                password_hashes.entry(hash).or_default().push(entry);
            }
        }

        password_hashes
            .into_iter()
            .filter(|(_, entries)| entries.len() > 1)
            .map(|(_, entries)| {
                let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
                AiSuggestion {
                    id: Uuid::new_v4(),
                    entry_id: None,
                    suggestion_type: SuggestionType::DuplicatePassword,
                    message: format!(
                        "Duplicate password found in: {}. Using unique passwords for each account is recommended.",
                        names.join(", ")
                    ),
                    priority: SuggestionPriority::High,
                    created_at: Utc::now(),
                    dismissed: false,
                    action_taken: false,
                }
            })
            .collect()
    }

    /// Check for passwords needing rotation
    fn check_rotation_needed(&self, entries: &[VaultEntry]) -> Vec<AiSuggestion> {
        entries
            .iter()
            .filter(|e| e.needs_rotation())
            .map(|entry| {
                let days_overdue = entry.days_until_rotation().map(|d| -d).unwrap_or(0);

                AiSuggestion {
                    id: Uuid::new_v4(),
                    entry_id: Some(entry.id),
                    suggestion_type: SuggestionType::RotatePassword,
                    message: format!(
                        "'{}' password is {} days overdue for rotation.",
                        entry.name, days_overdue
                    ),
                    priority: if days_overdue > 30 {
                        SuggestionPriority::High
                    } else {
                        SuggestionPriority::Medium
                    },
                    created_at: Utc::now(),
                    dismissed: false,
                    action_taken: false,
                }
            })
            .collect()
    }

    /// Check for unused entries
    fn check_unused_entries(&self, entries: &[VaultEntry]) -> Vec<AiSuggestion> {
        let threshold = Utc::now() - Duration::days(180); // 6 months

        entries
            .iter()
            .filter(|e| {
                e.last_accessed
                    .map(|t| t < threshold)
                    .unwrap_or(e.created_at < threshold)
            })
            .map(|entry| AiSuggestion {
                id: Uuid::new_v4(),
                entry_id: Some(entry.id),
                suggestion_type: SuggestionType::UnusedEntry,
                message: format!(
                    "'{}' hasn't been accessed in over 6 months. Consider reviewing if it's still needed.",
                    entry.name
                ),
                priority: SuggestionPriority::Low,
                created_at: Utc::now(),
                dismissed: false,
                action_taken: false,
            })
            .collect()
    }

    /// Get AI-powered suggestions (privacy-preserving)
    async fn get_ai_suggestions(&self, entries: &[VaultEntry]) -> AiResult<Vec<AiSuggestion>> {
        match &self.config.backend {
            AiBackend::Ollama { url, model } => self.query_ollama(url, model, entries).await,
            AiBackend::LlamaCpp { url, .. } => self.query_llamacpp(url, entries).await,
            AiBackend::Disabled => Ok(Vec::new()),
        }
    }

    /// Query local Ollama instance
    async fn query_ollama(
        &self,
        url: &str,
        model: &str,
        entries: &[VaultEntry],
    ) -> AiResult<Vec<AiSuggestion>> {
        // Prepare privacy-safe summary (no passwords, no sensitive data)
        let summary = self.prepare_safe_summary(entries);

        let prompt = format!(
            r#"You are a security advisor analyzing a password vault. Based on this summary, provide 1-3 actionable suggestions.

Vault Summary:
{}

Respond with a JSON array of suggestions, each with:
- "type": one of "organize", "security", "cleanup"
- "message": brief actionable suggestion
- "priority": one of "low", "medium", "high"

JSON only, no other text:"#,
            summary
        );

        let request = OllamaRequest {
            model: model.to_string(),
            prompt,
            stream: false,
        };

        let response = self
            .client
            .post(format!("{}/api/generate", url))
            .json(&request)
            .send()
            .await
            .map_err(|e| AiError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AiError::BackendUnavailable(format!(
                "Ollama returned status {}",
                response.status()
            )));
        }

        let ollama_response: OllamaResponse = response
            .json()
            .await
            .map_err(|e| AiError::InvalidResponse(e.to_string()))?;

        self.parse_ai_response(&ollama_response.response)
    }

    /// Query local llama.cpp server
    async fn query_llamacpp(
        &self,
        url: &str,
        entries: &[VaultEntry],
    ) -> AiResult<Vec<AiSuggestion>> {
        let summary = self.prepare_safe_summary(entries);

        let prompt = format!(
            r#"<|system|>You are a security advisor.</s>
<|user|>Analyze this vault and suggest improvements:
{}
Respond with JSON array of suggestions.</s>
<|assistant|>"#,
            summary
        );

        let request = LlamaCppRequest {
            prompt,
            n_predict: 256,
            temperature: 0.3,
            stop: vec!["</s>".to_string()],
        };

        let response = self
            .client
            .post(format!("{}/completion", url))
            .json(&request)
            .send()
            .await
            .map_err(|e| AiError::RequestFailed(e.to_string()))?;

        let llama_response: LlamaCppResponse = response
            .json()
            .await
            .map_err(|e| AiError::InvalidResponse(e.to_string()))?;

        self.parse_ai_response(&llama_response.content)
    }

    /// Prepare a privacy-safe summary (no actual passwords or secrets)
    fn prepare_safe_summary(&self, entries: &[VaultEntry]) -> String {
        let total = entries.len();
        let by_type: HashMap<String, usize> = entries.iter().fold(HashMap::new(), |mut acc, e| {
            *acc.entry(e.entry_type.to_string()).or_insert(0) += 1;
            acc
        });

        let weak_count = entries
            .iter()
            .filter(|e| {
                e.password_strength
                    .as_ref()
                    .map(|s| *s <= PasswordStrength::Weak)
                    .unwrap_or(false)
            })
            .count();

        let needs_rotation = entries.iter().filter(|e| e.needs_rotation()).count();

        let old_entries = entries
            .iter()
            .filter(|e| {
                e.last_accessed
                    .map(|t| t < Utc::now() - Duration::days(180))
                    .unwrap_or(false)
            })
            .count();

        let folders: Vec<_> = entries
            .iter()
            .filter_map(|e| e.folder.as_ref())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let tags: Vec<_> = entries
            .iter()
            .flat_map(|e| e.tags.iter())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .take(10)
            .collect();

        format!(
            r#"Total entries: {}
Entry types: {:?}
Weak passwords: {}
Needing rotation: {}
Not accessed in 6+ months: {}
Folders in use: {:?}
Common tags: {:?}"#,
            total, by_type, weak_count, needs_rotation, old_entries, folders, tags
        )
    }

    /// Parse AI response into suggestions
    fn parse_ai_response(&self, response: &str) -> AiResult<Vec<AiSuggestion>> {
        // Try to extract JSON from response
        let json_start = response.find('[').unwrap_or(0);
        let json_end = response.rfind(']').map(|i| i + 1).unwrap_or(response.len());
        let json_str = &response[json_start..json_end];

        let parsed: Vec<AiSuggestionRaw> =
            serde_json::from_str(json_str).map_err(|e| AiError::InvalidResponse(e.to_string()))?;

        Ok(parsed
            .into_iter()
            .map(|raw| AiSuggestion {
                id: Uuid::new_v4(),
                entry_id: None,
                suggestion_type: SuggestionType::OrganizeSuggestion,
                message: raw.message,
                priority: match raw.priority.to_lowercase().as_str() {
                    "high" => SuggestionPriority::High,
                    "low" => SuggestionPriority::Low,
                    _ => SuggestionPriority::Medium,
                },
                created_at: Utc::now(),
                dismissed: false,
                action_taken: false,
            })
            .collect())
    }

    /// Hash password for duplicate detection (never leaves local)
    fn hash_password(password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Check if password has been breached (k-anonymity, safe)
    pub async fn check_breach(&self, password: &str) -> AiResult<bool> {
        if !self.config.check_breaches {
            return Ok(false);
        }

        // Use k-anonymity: only send first 5 chars of SHA1 hash
        use sha1::{Digest as Sha1Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = hex::encode(hasher.finalize()).to_uppercase();

        let prefix = &hash[..5];
        let suffix = &hash[5..];

        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
        let response = self
            .client
            .get(&url)
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(|e| AiError::RequestFailed(e.to_string()))?;

        let text = response
            .text()
            .await
            .map_err(|e| AiError::InvalidResponse(e.to_string()))?;

        // Check if our suffix appears in the response
        for line in text.lines() {
            if let Some((hash_suffix, _count)) = line.split_once(':') {
                if hash_suffix == suffix {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Generate a smart password based on site requirements
    pub async fn generate_smart_password(&self, _site_url: Option<&str>) -> String {
        // Default strong password
        let generator = crate::crypto::PasswordGenerator::new(20);

        // Could query AI for site-specific requirements, but for now just generate
        generator.generate()
    }
}

/// Ollama API request
#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

/// Ollama API response
#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

/// llama.cpp API request
#[derive(Serialize)]
struct LlamaCppRequest {
    prompt: String,
    n_predict: u32,
    temperature: f32,
    stop: Vec<String>,
}

/// llama.cpp API response
#[derive(Deserialize)]
struct LlamaCppResponse {
    content: String,
}

/// Raw AI suggestion from response
#[derive(Deserialize)]
struct AiSuggestionRaw {
    message: String,
    priority: String,
    #[serde(default)]
    #[allow(dead_code)]
    r#type: String,
}

// Hex encoding
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_analyzer() {
        let ai = PasswordAi::new(AiConfig::default());

        let entries = vec![
            VaultEntry::new("Test1", crate::models::EntryType::Password).with_password("123456"),
            VaultEntry::new("Test2", crate::models::EntryType::Password)
                .with_password("correct-horse-battery-staple"),
        ];

        let weak = ai.check_weak_passwords(&entries);
        assert!(!weak.is_empty());
    }

    #[test]
    fn test_duplicate_detection() {
        let ai = PasswordAi::new(AiConfig::default());

        let entries = vec![
            VaultEntry::new("Site1", crate::models::EntryType::Password)
                .with_password("same_password"),
            VaultEntry::new("Site2", crate::models::EntryType::Password)
                .with_password("same_password"),
            VaultEntry::new("Site3", crate::models::EntryType::Password)
                .with_password("different_password"),
        ];

        let duplicates = ai.check_duplicates(&entries);
        assert_eq!(duplicates.len(), 1);
    }

    #[test]
    fn test_safe_summary() {
        let ai = PasswordAi::new(AiConfig::default());

        let entries = vec![
            VaultEntry::new("GitHub", crate::models::EntryType::Password)
                .with_password("super_secret_123")
                .with_tags(vec!["work".to_string()]),
        ];

        let summary = ai.prepare_safe_summary(&entries);
        assert!(!summary.contains("super_secret"));
        assert!(summary.contains("Total entries: 1"));
    }
}
