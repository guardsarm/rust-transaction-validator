//! AML/KYC compliance checks

use crate::Transaction;
use serde::{Deserialize, Serialize};

/// AML compliance checker
pub struct AMLChecker {
    /// Suspicious activity thresholds
    thresholds: AMLThresholds,
    /// Sanctioned entities list
    sanctioned_entities: Vec<String>,
}

/// AML thresholds (FinCEN guidelines)
#[derive(Debug, Clone)]
pub struct AMLThresholds {
    /// Currency Transaction Report threshold (USD)
    pub ctr_threshold: f64,
    /// Suspicious Activity Report threshold (USD)
    pub sar_threshold: f64,
    /// Structuring detection threshold
    pub structuring_threshold: f64,
}

impl Default for AMLThresholds {
    fn default() -> Self {
        Self {
            ctr_threshold: 10000.0,        // FinCEN CTR requirement
            sar_threshold: 5000.0,         // FinCEN SAR guideline
            structuring_threshold: 9500.0, // Just under $10k
        }
    }
}

/// AML compliance result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AMLResult {
    pub compliant: bool,
    pub requires_ctr: bool,
    pub requires_sar: bool,
    pub red_flags: Vec<AMLRedFlag>,
    pub risk_score: u8,
}

/// AML red flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AMLRedFlag {
    pub flag_type: RedFlagType,
    pub description: String,
    pub severity: AlertSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RedFlagType {
    PotentialStructuring,
    HighValueTransaction,
    SanctionedEntity,
    RapidMovement,
    UnusualPattern,
    CashIntensive,
    CrossBorder,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AMLChecker {
    /// Create new AML checker
    pub fn new() -> Self {
        Self {
            thresholds: AMLThresholds::default(),
            sanctioned_entities: vec![
                "OFAC-SANCTIONED-001".to_string(),
                "SANCTIONED-ENTITY-002".to_string(),
            ],
        }
    }

    /// Check transaction for AML compliance
    pub fn check_compliance(&self, transaction: &Transaction) -> AMLResult {
        let mut red_flags = Vec::new();
        let mut risk_score = 0u8;

        // Check if CTR required (>$10,000)
        let requires_ctr = transaction.amount >= self.thresholds.ctr_threshold;

        // Check if SAR may be required
        let mut requires_sar = false;

        // Structuring detection (amounts just below $10k)
        if self.is_potential_structuring(transaction) {
            red_flags.push(AMLRedFlag {
                flag_type: RedFlagType::PotentialStructuring,
                description: format!(
                    "Amount {} is just below CTR threshold (potential structuring)",
                    transaction.amount
                ),
                severity: AlertSeverity::High,
            });
            risk_score += 35;
            requires_sar = true;
        }

        // High value transaction
        if transaction.amount >= self.thresholds.ctr_threshold {
            red_flags.push(AMLRedFlag {
                flag_type: RedFlagType::HighValueTransaction,
                description: format!(
                    "High value transaction: {} (CTR required)",
                    transaction.amount
                ),
                severity: AlertSeverity::Medium,
            });
            risk_score += 15;
        }

        // Sanctioned entity check
        let from_sanctioned = transaction
            .from_account
            .as_deref()
            .map(|a| self.is_sanctioned_entity(a))
            .unwrap_or(false);
        let to_sanctioned = transaction
            .to_account
            .as_deref()
            .map(|a| self.is_sanctioned_entity(a))
            .unwrap_or(false);
        if from_sanctioned || to_sanctioned {
            red_flags.push(AMLRedFlag {
                flag_type: RedFlagType::SanctionedEntity,
                description: "Transaction involves sanctioned entity".to_string(),
                severity: AlertSeverity::Critical,
            });
            risk_score = 100;
            requires_sar = true;
        }

        // Cross-border transaction check
        if let Some(ref metadata) = transaction.metadata {
            if metadata
                .get("cross_border")
                .map(|v| v == "true")
                .unwrap_or(false)
            {
                red_flags.push(AMLRedFlag {
                    flag_type: RedFlagType::CrossBorder,
                    description: "Cross-border transaction requires additional due diligence"
                        .to_string(),
                    severity: AlertSeverity::Medium,
                });
                risk_score += 20;
            }
        }

        // Cash intensive check
        if matches!(
            transaction.transaction_type,
            crate::TransactionType::Deposit | crate::TransactionType::Withdrawal
        ) && transaction.amount >= 5000.0
        {
            red_flags.push(AMLRedFlag {
                flag_type: RedFlagType::CashIntensive,
                description: format!(
                    "Large cash {} of {}",
                    transaction.transaction_type, transaction.amount
                ),
                severity: AlertSeverity::High,
            });
            risk_score += 25;
        }

        AMLResult {
            compliant: risk_score < 75,
            requires_ctr,
            requires_sar,
            red_flags,
            risk_score: risk_score.min(100),
        }
    }

    fn is_potential_structuring(&self, transaction: &Transaction) -> bool {
        transaction.amount >= self.thresholds.structuring_threshold
            && transaction.amount < self.thresholds.ctr_threshold
    }

    fn is_sanctioned_entity(&self, entity: &str) -> bool {
        self.sanctioned_entities.iter().any(|s| entity.contains(s))
    }

    /// Add sanctioned entity to list
    pub fn add_sanctioned_entity(&mut self, entity: String) {
        if !self.sanctioned_entities.contains(&entity) {
            self.sanctioned_entities.push(entity);
        }
    }

    /// Check if entity is on sanctions list
    pub fn check_sanctions_list(&self, entity: &str) -> bool {
        self.is_sanctioned_entity(entity)
    }
}

impl Default for AMLChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// KYC (Know Your Customer) validator
pub struct KYCValidator;

impl KYCValidator {
    /// Validate customer information completeness
    pub fn validate_customer_data(customer_data: &serde_json::Value) -> KYCValidationResult {
        let mut missing_fields = Vec::new();
        let mut warnings = Vec::new();

        // Required fields for KYC
        let required = [
            "full_name",
            "date_of_birth",
            "address",
            "id_number",
            "id_type",
        ];

        for field in &required {
            if customer_data.get(field).is_none() {
                missing_fields.push(field.to_string());
            }
        }

        // Check for enhanced due diligence triggers
        if let Some(country) = customer_data.get("country").and_then(|v| v.as_str()) {
            if Self::is_high_risk_jurisdiction(country) {
                warnings.push(
                    "Customer from high-risk jurisdiction - Enhanced Due Diligence required"
                        .to_string(),
                );
            }
        }

        if let Some(pep) = customer_data
            .get("politically_exposed_person")
            .and_then(|v| v.as_bool())
        {
            if pep {
                warnings.push(
                    "Politically Exposed Person - Enhanced Due Diligence required".to_string(),
                );
            }
        }

        let requires_enhanced_dd = !warnings.is_empty();
        KYCValidationResult {
            valid: missing_fields.is_empty(),
            missing_fields,
            warnings,
            requires_enhanced_dd,
        }
    }

    fn is_high_risk_jurisdiction(country: &str) -> bool {
        // Simplified check
        matches!(country, "KP" | "IR" | "SY" | "CU" | "SD")
    }
}

/// KYC validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KYCValidationResult {
    pub valid: bool,
    pub missing_fields: Vec<String>,
    pub warnings: Vec<String>,
    pub requires_enhanced_dd: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_transaction(amount: f64, txn_type: crate::TransactionType) -> Transaction {
        Transaction {
            transaction_id: "TXN-001".to_string(),
            from_account: Some("ACC-123".to_string()),
            to_account: Some("ACC-456".to_string()),
            amount,
            currency: "USD".to_string(),
            timestamp: Utc::now(),
            transaction_type: txn_type,
            user_id: "USER-001".to_string(),
            metadata: None,
        }
    }

    #[test]
    fn test_ctr_requirement() {
        let checker = AMLChecker::new();
        let txn = create_test_transaction(15000.0, crate::TransactionType::Transfer);
        let result = checker.check_compliance(&txn);

        assert!(result.requires_ctr);
        assert!(result
            .red_flags
            .iter()
            .any(|f| f.flag_type == RedFlagType::HighValueTransaction));
    }

    #[test]
    fn test_structuring_detection() {
        let checker = AMLChecker::new();
        let txn = create_test_transaction(9800.0, crate::TransactionType::Transfer);
        let result = checker.check_compliance(&txn);

        assert!(result.requires_sar);
        assert!(result
            .red_flags
            .iter()
            .any(|f| f.flag_type == RedFlagType::PotentialStructuring));
    }

    #[test]
    fn test_sanctioned_entity() {
        let checker = AMLChecker::new();
        let mut txn = create_test_transaction(1000.0, crate::TransactionType::Transfer);
        txn.from_account = Some("OFAC-SANCTIONED-001".to_string());

        let result = checker.check_compliance(&txn);

        assert!(!result.compliant);
        assert_eq!(result.risk_score, 100);
        assert!(result
            .red_flags
            .iter()
            .any(|f| f.flag_type == RedFlagType::SanctionedEntity));
    }

    #[test]
    fn test_cash_intensive() {
        let checker = AMLChecker::new();
        let txn = create_test_transaction(8000.0, crate::TransactionType::Deposit);
        let result = checker.check_compliance(&txn);

        assert!(result
            .red_flags
            .iter()
            .any(|f| f.flag_type == RedFlagType::CashIntensive));
    }

    #[test]
    fn test_cross_border() {
        let checker = AMLChecker::new();
        let mut txn = create_test_transaction(5000.0, crate::TransactionType::Transfer);
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("cross_border".to_string(), "true".to_string());
        txn.metadata = Some(metadata);

        let result = checker.check_compliance(&txn);

        assert!(result
            .red_flags
            .iter()
            .any(|f| f.flag_type == RedFlagType::CrossBorder));
    }

    #[test]
    fn test_kyc_validation() {
        let complete_data = serde_json::json!({
            "full_name": "John Doe",
            "date_of_birth": "1990-01-01",
            "address": "123 Main St",
            "id_number": "123456789",
            "id_type": "passport",
            "country": "US"
        });

        let result = KYCValidator::validate_customer_data(&complete_data);
        assert!(result.valid);
        assert!(result.missing_fields.is_empty());
    }

    #[test]
    fn test_kyc_missing_fields() {
        let incomplete_data = serde_json::json!({
            "full_name": "John Doe"
        });

        let result = KYCValidator::validate_customer_data(&incomplete_data);
        assert!(!result.valid);
        assert!(!result.missing_fields.is_empty());
    }

    #[test]
    fn test_kyc_enhanced_dd() {
        let pep_data = serde_json::json!({
            "full_name": "John Doe",
            "date_of_birth": "1990-01-01",
            "address": "123 Main St",
            "id_number": "123456789",
            "id_type": "passport",
            "politically_exposed_person": true
        });

        let result = KYCValidator::validate_customer_data(&pep_data);
        assert!(result.requires_enhanced_dd);
        assert!(!result.warnings.is_empty());
    }
}
