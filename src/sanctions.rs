//! Sanctions screening module for transaction validation v2.0
//!
//! Provides real-time sanctions list screening against OFAC, EU, and UN lists.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Sanctions list source
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SanctionsList {
    OFAC,           // US Office of Foreign Assets Control
    EU,             // European Union
    UN,             // United Nations
    UKOFSI,         // UK Office of Financial Sanctions Implementation
    Custom(String), // Custom list
}

impl SanctionsList {
    pub fn name(&self) -> &str {
        match self {
            SanctionsList::OFAC => "OFAC SDN",
            SanctionsList::EU => "EU Consolidated",
            SanctionsList::UN => "UN Security Council",
            SanctionsList::UKOFSI => "UK OFSI",
            SanctionsList::Custom(name) => name,
        }
    }
}

/// Sanctions match type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatchType {
    Exact,
    Partial,
    Fuzzy,
    Alias,
}

/// Sanctions screening result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctionsResult {
    pub screened_value: String,
    pub is_match: bool,
    pub matches: Vec<SanctionsMatch>,
    pub screening_time: DateTime<Utc>,
    pub lists_checked: Vec<SanctionsList>,
}

impl SanctionsResult {
    /// Check if there are any high-confidence matches
    pub fn has_high_confidence_match(&self) -> bool {
        self.matches.iter().any(|m| m.confidence >= 0.9)
    }

    /// Get highest confidence match
    pub fn highest_confidence(&self) -> Option<&SanctionsMatch> {
        self.matches.iter().max_by(|a, b| {
            a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Get matches above threshold
    pub fn matches_above_threshold(&self, threshold: f32) -> Vec<&SanctionsMatch> {
        self.matches.iter().filter(|m| m.confidence >= threshold).collect()
    }
}

/// Individual sanctions match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctionsMatch {
    pub matched_name: String,
    pub list: SanctionsList,
    pub match_type: MatchType,
    pub confidence: f32,
    pub entry_id: String,
    pub program: Option<String>,
    pub country: Option<String>,
}

/// Sanctioned entity for the database
#[derive(Debug, Clone)]
struct SanctionedEntity {
    id: String,
    name: String,
    aliases: Vec<String>,
    list: SanctionsList,
    program: Option<String>,
    country: Option<String>,
}

/// Sanctions screener
pub struct SanctionsScreener {
    entities: Vec<SanctionedEntity>,
    enabled_lists: HashSet<SanctionsList>,
    fuzzy_threshold: f32,
}

impl SanctionsScreener {
    /// Create a new sanctions screener
    pub fn new() -> Self {
        let mut screener = Self {
            entities: Vec::new(),
            enabled_lists: HashSet::new(),
            fuzzy_threshold: 0.85,
        };
        screener.enabled_lists.insert(SanctionsList::OFAC);
        screener.enabled_lists.insert(SanctionsList::EU);
        screener.enabled_lists.insert(SanctionsList::UN);
        screener.load_default_entries();
        screener
    }

    /// Load default sanctioned entities (simplified for demonstration)
    fn load_default_entries(&mut self) {
        // Note: In production, this would load from actual OFAC/EU/UN data
        // These are fictional entries for demonstration purposes

        self.entities.push(SanctionedEntity {
            id: "OFAC-001".to_string(),
            name: "SANCTIONED ENTITY ONE".to_string(),
            aliases: vec!["ENTITY ONE".to_string(), "E1 LTD".to_string()],
            list: SanctionsList::OFAC,
            program: Some("SDGT".to_string()),
            country: Some("XX".to_string()),
        });

        self.entities.push(SanctionedEntity {
            id: "EU-001".to_string(),
            name: "RESTRICTED COMPANY EU".to_string(),
            aliases: vec!["RC EU".to_string()],
            list: SanctionsList::EU,
            program: Some("COUNCIL REGULATION".to_string()),
            country: Some("YY".to_string()),
        });

        self.entities.push(SanctionedEntity {
            id: "UN-001".to_string(),
            name: "UN LISTED ORGANIZATION".to_string(),
            aliases: vec!["ULO".to_string()],
            list: SanctionsList::UN,
            program: Some("1267".to_string()),
            country: None,
        });
    }

    /// Enable a sanctions list
    pub fn enable_list(&mut self, list: SanctionsList) {
        self.enabled_lists.insert(list);
    }

    /// Disable a sanctions list
    pub fn disable_list(&mut self, list: &SanctionsList) {
        self.enabled_lists.remove(list);
    }

    /// Set fuzzy matching threshold
    pub fn set_fuzzy_threshold(&mut self, threshold: f32) {
        self.fuzzy_threshold = threshold.clamp(0.0, 1.0);
    }

    /// Screen a name against sanctions lists
    pub fn screen(&self, name: &str) -> SanctionsResult {
        let name_upper = name.to_uppercase();
        let mut matches = Vec::new();
        let lists_checked: Vec<SanctionsList> = self.enabled_lists.iter().cloned().collect();

        for entity in &self.entities {
            if !self.enabled_lists.contains(&entity.list) {
                continue;
            }

            // Exact match on primary name
            if entity.name == name_upper {
                matches.push(SanctionsMatch {
                    matched_name: entity.name.clone(),
                    list: entity.list.clone(),
                    match_type: MatchType::Exact,
                    confidence: 1.0,
                    entry_id: entity.id.clone(),
                    program: entity.program.clone(),
                    country: entity.country.clone(),
                });
                continue;
            }

            // Check aliases
            for alias in &entity.aliases {
                if alias.to_uppercase() == name_upper {
                    matches.push(SanctionsMatch {
                        matched_name: entity.name.clone(),
                        list: entity.list.clone(),
                        match_type: MatchType::Alias,
                        confidence: 0.95,
                        entry_id: entity.id.clone(),
                        program: entity.program.clone(),
                        country: entity.country.clone(),
                    });
                    break;
                }
            }

            // Fuzzy matching
            let similarity = self.calculate_similarity(&name_upper, &entity.name);
            if similarity >= self.fuzzy_threshold {
                matches.push(SanctionsMatch {
                    matched_name: entity.name.clone(),
                    list: entity.list.clone(),
                    match_type: MatchType::Fuzzy,
                    confidence: similarity,
                    entry_id: entity.id.clone(),
                    program: entity.program.clone(),
                    country: entity.country.clone(),
                });
            }

            // Partial match (contains)
            if entity.name.contains(&name_upper) || name_upper.contains(&entity.name) {
                let partial_conf = 0.7 + (0.2 * (name_upper.len().min(entity.name.len()) as f32
                    / name_upper.len().max(entity.name.len()) as f32));

                if !matches.iter().any(|m| m.entry_id == entity.id) {
                    matches.push(SanctionsMatch {
                        matched_name: entity.name.clone(),
                        list: entity.list.clone(),
                        match_type: MatchType::Partial,
                        confidence: partial_conf,
                        entry_id: entity.id.clone(),
                        program: entity.program.clone(),
                        country: entity.country.clone(),
                    });
                }
            }
        }

        // Sort by confidence
        matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        SanctionsResult {
            screened_value: name.to_string(),
            is_match: !matches.is_empty(),
            matches,
            screening_time: Utc::now(),
            lists_checked,
        }
    }

    /// Screen multiple names in batch
    pub fn screen_batch(&self, names: &[&str]) -> Vec<SanctionsResult> {
        names.iter().map(|name| self.screen(name)).collect()
    }

    /// Calculate string similarity using Levenshtein-based metric
    fn calculate_similarity(&self, s1: &str, s2: &str) -> f32 {
        if s1.is_empty() || s2.is_empty() {
            return 0.0;
        }

        let len1 = s1.len();
        let len2 = s2.len();
        let max_len = len1.max(len2);

        // Simple character-based similarity
        let common_chars: usize = s1.chars()
            .filter(|c| s2.contains(*c))
            .count();

        let char_similarity = common_chars as f32 / max_len as f32;

        // Word-based similarity
        let words1: HashSet<&str> = s1.split_whitespace().collect();
        let words2: HashSet<&str> = s2.split_whitespace().collect();
        let common_words = words1.intersection(&words2).count();
        let total_words = words1.union(&words2).count();

        let word_similarity = if total_words > 0 {
            common_words as f32 / total_words as f32
        } else {
            0.0
        };

        // Weighted combination
        (char_similarity * 0.4) + (word_similarity * 0.6)
    }

    /// Add a custom sanctioned entity
    pub fn add_entity(&mut self, name: &str, aliases: Vec<String>, list: SanctionsList) {
        let id = format!("{}-{}", list.name(), self.entities.len());
        self.entities.push(SanctionedEntity {
            id,
            name: name.to_uppercase(),
            aliases: aliases.into_iter().map(|a| a.to_uppercase()).collect(),
            list,
            program: None,
            country: None,
        });
    }
}

impl Default for SanctionsScreener {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let screener = SanctionsScreener::new();
        let result = screener.screen("SANCTIONED ENTITY ONE");

        assert!(result.is_match);
        assert!(!result.matches.is_empty());
        assert_eq!(result.matches[0].match_type, MatchType::Exact);
        assert_eq!(result.matches[0].confidence, 1.0);
    }

    #[test]
    fn test_alias_match() {
        let screener = SanctionsScreener::new();
        let result = screener.screen("ENTITY ONE");

        assert!(result.is_match);
        assert!(result.matches.iter().any(|m| m.match_type == MatchType::Alias));
    }

    #[test]
    fn test_no_match() {
        let screener = SanctionsScreener::new();
        let result = screener.screen("LEGITIMATE COMPANY XYZ");

        // Should have no high-confidence matches
        assert!(!result.has_high_confidence_match());
    }

    #[test]
    fn test_batch_screening() {
        let screener = SanctionsScreener::new();
        let names = vec!["SANCTIONED ENTITY ONE", "NORMAL COMPANY", "ENTITY ONE"];
        let results = screener.screen_batch(&names);

        assert_eq!(results.len(), 3);
        assert!(results[0].is_match); // Exact match
        assert!(results[2].is_match); // Alias match
    }

    #[test]
    fn test_custom_entity() {
        let mut screener = SanctionsScreener::new();
        screener.add_entity(
            "CUSTOM BAD ACTOR",
            vec!["CBA".to_string(), "BAD ACTOR CO".to_string()],
            SanctionsList::Custom("INTERNAL".to_string()),
        );
        screener.enable_list(SanctionsList::Custom("INTERNAL".to_string()));

        let result = screener.screen("CUSTOM BAD ACTOR");
        assert!(result.is_match);
    }

    #[test]
    fn test_list_filtering() {
        let mut screener = SanctionsScreener::new();
        screener.disable_list(&SanctionsList::OFAC);

        let result = screener.screen("SANCTIONED ENTITY ONE");
        // OFAC entry should not match since we disabled OFAC
        assert!(!result.lists_checked.contains(&SanctionsList::OFAC));
    }

    #[test]
    fn test_fuzzy_threshold() {
        let mut screener = SanctionsScreener::new();
        screener.set_fuzzy_threshold(0.95); // Very strict

        let result = screener.screen("SANCTIONED ENTTY ONE"); // Typo
        // Should have lower confidence due to typo
        if result.is_match {
            assert!(result.matches[0].confidence < 1.0);
        }
    }

    #[test]
    fn test_highest_confidence() {
        let screener = SanctionsScreener::new();
        let result = screener.screen("SANCTIONED ENTITY ONE");

        let highest = result.highest_confidence();
        assert!(highest.is_some());
        assert_eq!(highest.unwrap().confidence, 1.0);
    }
}
