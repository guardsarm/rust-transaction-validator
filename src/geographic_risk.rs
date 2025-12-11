//! Geographic risk scoring module for transaction validation v2.0
//!
//! Provides country and jurisdiction-based risk assessment.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Country risk level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CountryRiskLevel {
    Low,
    Medium,
    High,
    Prohibited,
}

/// Country risk entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountryRisk {
    pub country_code: String,
    pub country_name: String,
    pub risk_level: CountryRiskLevel,
    pub risk_score: u8,
    pub factors: Vec<String>,
    pub fatf_status: Option<String>,
    pub sanctions_programs: Vec<String>,
}

impl CountryRisk {
    /// Check if country is prohibited
    pub fn is_prohibited(&self) -> bool {
        self.risk_level == CountryRiskLevel::Prohibited
    }

    /// Check if enhanced due diligence is required
    pub fn requires_edd(&self) -> bool {
        matches!(self.risk_level, CountryRiskLevel::High | CountryRiskLevel::Prohibited)
    }
}

/// Jurisdiction risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JurisdictionRisk {
    pub jurisdiction: String,
    pub is_tax_haven: bool,
    pub is_offshore: bool,
    pub is_fatf_greylist: bool,
    pub is_fatf_blacklist: bool,
    pub transparency_score: u8, // 0-100
    pub regulatory_strength: u8, // 0-100
    pub overall_risk: CountryRiskLevel,
}

impl JurisdictionRisk {
    /// Calculate combined risk score
    pub fn risk_score(&self) -> u8 {
        let mut score = 0u8;

        if self.is_tax_haven {
            score = score.saturating_add(20);
        }
        if self.is_offshore {
            score = score.saturating_add(15);
        }
        if self.is_fatf_greylist {
            score = score.saturating_add(30);
        }
        if self.is_fatf_blacklist {
            score = score.saturating_add(50);
        }

        // Lower transparency increases risk
        score = score.saturating_add((100 - self.transparency_score) / 4);

        // Lower regulatory strength increases risk
        score = score.saturating_add((100 - self.regulatory_strength) / 4);

        score.min(100)
    }
}

/// Geographic risk scorer
pub struct GeographicRiskScorer {
    country_risks: HashMap<String, CountryRisk>,
    jurisdiction_risks: HashMap<String, JurisdictionRisk>,
}

impl GeographicRiskScorer {
    /// Create a new geographic risk scorer
    pub fn new() -> Self {
        let mut scorer = Self {
            country_risks: HashMap::new(),
            jurisdiction_risks: HashMap::new(),
        };
        scorer.load_default_risks();
        scorer
    }

    /// Load default country and jurisdiction risks
    fn load_default_risks(&mut self) {
        // High-risk countries (simplified list)
        self.add_country_risk(CountryRisk {
            country_code: "IR".to_string(),
            country_name: "Iran".to_string(),
            risk_level: CountryRiskLevel::Prohibited,
            risk_score: 100,
            factors: vec![
                "FATF Blacklist".to_string(),
                "US Comprehensive Sanctions".to_string(),
            ],
            fatf_status: Some("Blacklist".to_string()),
            sanctions_programs: vec!["OFAC Iran Sanctions".to_string()],
        });

        self.add_country_risk(CountryRisk {
            country_code: "KP".to_string(),
            country_name: "North Korea".to_string(),
            risk_level: CountryRiskLevel::Prohibited,
            risk_score: 100,
            factors: vec![
                "FATF Blacklist".to_string(),
                "UN Sanctions".to_string(),
            ],
            fatf_status: Some("Blacklist".to_string()),
            sanctions_programs: vec!["OFAC North Korea".to_string(), "UN Sanctions".to_string()],
        });

        self.add_country_risk(CountryRisk {
            country_code: "SY".to_string(),
            country_name: "Syria".to_string(),
            risk_level: CountryRiskLevel::Prohibited,
            risk_score: 95,
            factors: vec![
                "US Comprehensive Sanctions".to_string(),
                "EU Sanctions".to_string(),
            ],
            fatf_status: None,
            sanctions_programs: vec!["OFAC Syria Sanctions".to_string()],
        });

        // High-risk countries
        self.add_country_risk(CountryRisk {
            country_code: "MM".to_string(),
            country_name: "Myanmar".to_string(),
            risk_level: CountryRiskLevel::High,
            risk_score: 80,
            factors: vec!["FATF Greylist".to_string(), "Targeted Sanctions".to_string()],
            fatf_status: Some("Greylist".to_string()),
            sanctions_programs: vec![],
        });

        self.add_country_risk(CountryRisk {
            country_code: "YE".to_string(),
            country_name: "Yemen".to_string(),
            risk_level: CountryRiskLevel::High,
            risk_score: 75,
            factors: vec!["Conflict Zone".to_string(), "Targeted Sanctions".to_string()],
            fatf_status: None,
            sanctions_programs: vec![],
        });

        // Medium-risk countries
        self.add_country_risk(CountryRisk {
            country_code: "PK".to_string(),
            country_name: "Pakistan".to_string(),
            risk_level: CountryRiskLevel::Medium,
            risk_score: 55,
            factors: vec!["FATF Greylist".to_string()],
            fatf_status: Some("Greylist".to_string()),
            sanctions_programs: vec![],
        });

        // Low-risk countries
        self.add_country_risk(CountryRisk {
            country_code: "US".to_string(),
            country_name: "United States".to_string(),
            risk_level: CountryRiskLevel::Low,
            risk_score: 10,
            factors: vec![],
            fatf_status: None,
            sanctions_programs: vec![],
        });

        self.add_country_risk(CountryRisk {
            country_code: "GB".to_string(),
            country_name: "United Kingdom".to_string(),
            risk_level: CountryRiskLevel::Low,
            risk_score: 10,
            factors: vec![],
            fatf_status: None,
            sanctions_programs: vec![],
        });

        self.add_country_risk(CountryRisk {
            country_code: "DE".to_string(),
            country_name: "Germany".to_string(),
            risk_level: CountryRiskLevel::Low,
            risk_score: 10,
            factors: vec![],
            fatf_status: None,
            sanctions_programs: vec![],
        });

        // Offshore jurisdictions
        self.add_jurisdiction_risk(JurisdictionRisk {
            jurisdiction: "Cayman Islands".to_string(),
            is_tax_haven: true,
            is_offshore: true,
            is_fatf_greylist: false,
            is_fatf_blacklist: false,
            transparency_score: 60,
            regulatory_strength: 70,
            overall_risk: CountryRiskLevel::Medium,
        });

        self.add_jurisdiction_risk(JurisdictionRisk {
            jurisdiction: "British Virgin Islands".to_string(),
            is_tax_haven: true,
            is_offshore: true,
            is_fatf_greylist: false,
            is_fatf_blacklist: false,
            transparency_score: 50,
            regulatory_strength: 60,
            overall_risk: CountryRiskLevel::Medium,
        });

        self.add_jurisdiction_risk(JurisdictionRisk {
            jurisdiction: "Panama".to_string(),
            is_tax_haven: true,
            is_offshore: true,
            is_fatf_greylist: true,
            is_fatf_blacklist: false,
            transparency_score: 40,
            regulatory_strength: 50,
            overall_risk: CountryRiskLevel::High,
        });
    }

    /// Add a country risk entry
    pub fn add_country_risk(&mut self, risk: CountryRisk) {
        self.country_risks.insert(risk.country_code.clone(), risk);
    }

    /// Add a jurisdiction risk entry
    pub fn add_jurisdiction_risk(&mut self, risk: JurisdictionRisk) {
        self.jurisdiction_risks.insert(risk.jurisdiction.clone(), risk);
    }

    /// Get country risk by ISO code
    pub fn get_country_risk(&self, country_code: &str) -> Option<&CountryRisk> {
        self.country_risks.get(&country_code.to_uppercase())
    }

    /// Get jurisdiction risk
    pub fn get_jurisdiction_risk(&self, jurisdiction: &str) -> Option<&JurisdictionRisk> {
        self.jurisdiction_risks.get(jurisdiction)
    }

    /// Calculate transaction risk based on origin and destination countries
    pub fn calculate_transaction_risk(&self, origin: &str, destination: &str) -> TransactionGeographicRisk {
        let origin_risk = self.get_country_risk(origin);
        let dest_risk = self.get_country_risk(destination);

        let origin_score = origin_risk.map_or(50, |r| r.risk_score);
        let dest_score = dest_risk.map_or(50, |r| r.risk_score);

        // Use the higher of the two risks, weighted
        let combined_score = ((origin_score as u16 * 40 + dest_score as u16 * 60) / 100) as u8;

        let is_prohibited = origin_risk.map_or(false, |r| r.is_prohibited())
            || dest_risk.map_or(false, |r| r.is_prohibited());

        let requires_edd = origin_risk.map_or(false, |r| r.requires_edd())
            || dest_risk.map_or(false, |r| r.requires_edd());

        let risk_level = if is_prohibited {
            CountryRiskLevel::Prohibited
        } else if combined_score >= 70 {
            CountryRiskLevel::High
        } else if combined_score >= 40 {
            CountryRiskLevel::Medium
        } else {
            CountryRiskLevel::Low
        };

        TransactionGeographicRisk {
            origin_country: origin.to_string(),
            destination_country: destination.to_string(),
            origin_risk: origin_risk.cloned(),
            destination_risk: dest_risk.cloned(),
            combined_score,
            risk_level,
            is_prohibited,
            requires_edd,
        }
    }

    /// Get all prohibited countries
    pub fn get_prohibited_countries(&self) -> Vec<&CountryRisk> {
        self.country_risks
            .values()
            .filter(|r| r.risk_level == CountryRiskLevel::Prohibited)
            .collect()
    }

    /// Get all high-risk countries
    pub fn get_high_risk_countries(&self) -> Vec<&CountryRisk> {
        self.country_risks
            .values()
            .filter(|r| r.risk_level == CountryRiskLevel::High)
            .collect()
    }

    /// Check if a country is on any FATF list
    pub fn is_fatf_listed(&self, country_code: &str) -> Option<String> {
        self.get_country_risk(country_code)
            .and_then(|r| r.fatf_status.clone())
    }
}

impl Default for GeographicRiskScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Transaction geographic risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionGeographicRisk {
    pub origin_country: String,
    pub destination_country: String,
    pub origin_risk: Option<CountryRisk>,
    pub destination_risk: Option<CountryRisk>,
    pub combined_score: u8,
    pub risk_level: CountryRiskLevel,
    pub is_prohibited: bool,
    pub requires_edd: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prohibited_country() {
        let scorer = GeographicRiskScorer::new();

        let iran = scorer.get_country_risk("IR").unwrap();
        assert!(iran.is_prohibited());
        assert_eq!(iran.risk_level, CountryRiskLevel::Prohibited);
    }

    #[test]
    fn test_low_risk_country() {
        let scorer = GeographicRiskScorer::new();

        let us = scorer.get_country_risk("US").unwrap();
        assert_eq!(us.risk_level, CountryRiskLevel::Low);
        assert!(!us.is_prohibited());
        assert!(!us.requires_edd());
    }

    #[test]
    fn test_transaction_risk() {
        let scorer = GeographicRiskScorer::new();

        // Low-risk transaction
        let low_risk = scorer.calculate_transaction_risk("US", "GB");
        assert_eq!(low_risk.risk_level, CountryRiskLevel::Low);
        assert!(!low_risk.is_prohibited);

        // Prohibited transaction
        let prohibited = scorer.calculate_transaction_risk("US", "IR");
        assert!(prohibited.is_prohibited);
        assert_eq!(prohibited.risk_level, CountryRiskLevel::Prohibited);
    }

    #[test]
    fn test_high_risk_transaction() {
        let scorer = GeographicRiskScorer::new();

        let risk = scorer.calculate_transaction_risk("US", "MM");
        assert!(risk.requires_edd);
    }

    #[test]
    fn test_jurisdiction_risk() {
        let scorer = GeographicRiskScorer::new();

        let cayman = scorer.get_jurisdiction_risk("Cayman Islands").unwrap();
        assert!(cayman.is_tax_haven);
        assert!(cayman.is_offshore);

        let score = cayman.risk_score();
        assert!(score > 30); // Should have elevated risk
    }

    #[test]
    fn test_fatf_status() {
        let scorer = GeographicRiskScorer::new();

        let ir_status = scorer.is_fatf_listed("IR");
        assert_eq!(ir_status, Some("Blacklist".to_string()));

        let us_status = scorer.is_fatf_listed("US");
        assert_eq!(us_status, None);
    }

    #[test]
    fn test_prohibited_countries_list() {
        let scorer = GeographicRiskScorer::new();

        let prohibited = scorer.get_prohibited_countries();
        assert!(!prohibited.is_empty());

        let codes: Vec<&str> = prohibited.iter().map(|r| r.country_code.as_str()).collect();
        assert!(codes.contains(&"IR"));
        assert!(codes.contains(&"KP"));
    }

    #[test]
    fn test_unknown_country() {
        let scorer = GeographicRiskScorer::new();

        let risk = scorer.calculate_transaction_risk("XX", "YY");
        // Unknown countries should get medium risk by default
        assert_eq!(risk.combined_score, 50);
    }
}
