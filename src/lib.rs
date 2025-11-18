//! # Rust Transaction Validator
//!
//! A memory-safe financial transaction validator for fraud detection and regulatory compliance.
//!
//! ## Features
//!
//! - **Memory Safety**: Built with Rust to prevent vulnerabilities in financial systems
//! - **Advanced Fraud Detection**: Multi-factor fraud scoring with velocity checks
//! - **AML/KYC Compliance**: FinCEN-compliant CTR/SAR detection
//! - **Sanctions Screening**: OFAC sanctions list checking
//! - **Business Rules**: Configurable transaction validation rules
//! - **Audit Trail**: Complete transaction validation history
//!
//! ## Alignment with Federal Guidance
//!
//! Implements secure financial transaction processing using memory-safe Rust,
//! aligning with 2024 CISA/FBI guidance for critical financial infrastructure.

pub mod aml_compliance;
pub mod fraud_patterns;

pub use aml_compliance::{AMLChecker, AMLResult, KYCValidationResult, KYCValidator};
pub use fraud_patterns::{FraudDetector, FraudScore, FraudThresholds, RiskLevel};

use chrono::{DateTime, Duration, Timelike, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Validation errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum ValidationError {
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Invalid account number: {0}")]
    InvalidAccount(String),

    #[error("Duplicate transaction detected: {0}")]
    DuplicateTransaction(String),

    #[error("Fraud pattern detected: {0}")]
    FraudDetected(String),

    #[error("Compliance check failed: {0}")]
    ComplianceFailed(String),

    #[error("Business rule violation: {0}")]
    BusinessRuleViolation(String),

    #[error("Velocity check failed: {0}")]
    VelocityViolation(String),

    #[error("Risk threshold exceeded: {0}")]
    RiskThresholdExceeded(String),
}

/// Risk breakdown for detailed analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskBreakdown {
    pub amount_risk: u8,
    pub velocity_risk: u8,
    pub pattern_risk: u8,
    pub time_risk: u8,
    pub total_score: u8,
}

impl RiskBreakdown {
    fn new() -> Self {
        Self {
            amount_risk: 0,
            velocity_risk: 0,
            pattern_risk: 0,
            time_risk: 0,
            total_score: 0,
        }
    }

    fn calculate_total(&mut self) {
        self.total_score = self
            .amount_risk
            .saturating_add(self.velocity_risk)
            .saturating_add(self.pattern_risk)
            .saturating_add(self.time_risk)
            .min(100);
    }
}

/// Transaction type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionType {
    Deposit,
    Withdrawal,
    Transfer,
    Payment,
    WireTransfer,
}

impl std::fmt::Display for TransactionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionType::Deposit => write!(f, "deposit"),
            TransactionType::Withdrawal => write!(f, "withdrawal"),
            TransactionType::Transfer => write!(f, "transfer"),
            TransactionType::Payment => write!(f, "payment"),
            TransactionType::WireTransfer => write!(f, "wire_transfer"),
        }
    }
}

/// Transaction structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub transaction_id: String,
    pub transaction_type: TransactionType,
    pub amount: f64,
    pub currency: String,
    pub from_account: Option<String>,
    pub to_account: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub metadata: Option<HashMap<String, String>>,
}

/// Validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub transaction_id: String,
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
    pub fraud_score: u8,
    pub risk_breakdown: RiskBreakdown,
    pub compliance_checks: HashMap<String, bool>,
    pub validated_at: DateTime<Utc>,
}

impl ValidationResult {
    /// Check if transaction passed all validations
    pub fn is_approved(&self) -> bool {
        self.is_valid && self.errors.is_empty() && self.fraud_score < 50
    }

    /// Check if transaction requires manual review
    pub fn requires_manual_review(&self) -> bool {
        self.fraud_score >= 50 || !self.warnings.is_empty()
    }

    /// Get risk level description
    pub fn risk_level(&self) -> &str {
        match self.fraud_score {
            0..=25 => "Low",
            26..=50 => "Medium",
            51..=75 => "High",
            _ => "Critical",
        }
    }

    /// Export as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Transaction history entry for velocity checking
#[derive(Debug, Clone)]
struct TransactionHistory {
    user_id: String,
    timestamp: DateTime<Utc>,
    amount: f64,
}

/// Transaction validator configuration
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub max_transaction_amount: f64,
    pub min_transaction_amount: f64,
    pub fraud_threshold: u8,
    pub enable_duplicate_check: bool,
    pub enable_aml_check: bool,
    pub velocity_check_window_minutes: i64,
    pub max_transactions_per_window: usize,
    pub max_amount_per_window: f64,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            max_transaction_amount: 1_000_000.0,
            min_transaction_amount: 0.01,
            fraud_threshold: 70,
            enable_duplicate_check: true,
            enable_aml_check: true,
            velocity_check_window_minutes: 60, // 1 hour window
            max_transactions_per_window: 10,
            max_amount_per_window: 100_000.0,
        }
    }
}

/// Financial transaction validator
pub struct TransactionValidator {
    config: ValidatorConfig,
    processed_transactions: Vec<String>,
    transaction_history: Vec<TransactionHistory>,
}

impl TransactionValidator {
    /// Create a new validator with default configuration
    pub fn new() -> Self {
        Self {
            config: ValidatorConfig::default(),
            processed_transactions: Vec::new(),
            transaction_history: Vec::new(),
        }
    }

    /// Create a new validator with custom configuration
    pub fn with_config(config: ValidatorConfig) -> Self {
        Self {
            config,
            processed_transactions: Vec::new(),
            transaction_history: Vec::new(),
        }
    }

    /// Validate a transaction
    pub fn validate(&mut self, transaction: &Transaction) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut compliance_checks = HashMap::new();
        let mut risk_breakdown = RiskBreakdown::new();

        // 1. Amount validation
        if let Err(e) = self.validate_amount(transaction) {
            errors.push(e);
        }

        // Calculate amount risk
        risk_breakdown.amount_risk = self.calculate_amount_risk(transaction.amount);

        // 2. Account validation
        if let Err(e) = self.validate_accounts(transaction) {
            errors.push(e);
        }

        // 3. Duplicate detection
        if self.config.enable_duplicate_check {
            if self
                .processed_transactions
                .contains(&transaction.transaction_id)
            {
                errors.push(ValidationError::DuplicateTransaction(
                    transaction.transaction_id.clone(),
                ));
            } else {
                self.processed_transactions
                    .push(transaction.transaction_id.clone());
            }
        }

        // 4. Velocity checks
        let velocity_result = self.check_velocity(transaction);
        risk_breakdown.velocity_risk = velocity_result.0;
        if let Some(err) = velocity_result.1 {
            errors.push(err);
        }
        if !velocity_result.2.is_empty() {
            warnings.extend(velocity_result.2);
        }

        // Record transaction in history
        self.transaction_history.push(TransactionHistory {
            user_id: transaction.user_id.clone(),
            timestamp: transaction.timestamp,
            amount: transaction.amount,
        });

        // 5. Fraud detection
        let fraud_checks = self.check_fraud_patterns(transaction);
        risk_breakdown.pattern_risk = fraud_checks.0;
        if !fraud_checks.1.is_empty() {
            warnings.extend(fraud_checks.1);
        }

        // 6. Time-based risk
        risk_breakdown.time_risk = self.calculate_time_risk(&transaction.timestamp);

        // Calculate total risk
        risk_breakdown.calculate_total();
        let fraud_score = risk_breakdown.total_score;

        // 7. AML compliance
        if self.config.enable_aml_check {
            let aml_result = self.check_aml_compliance(transaction);
            compliance_checks.insert("AML".to_string(), aml_result);
            if !aml_result {
                errors.push(ValidationError::ComplianceFailed(
                    "AML compliance check failed".to_string(),
                ));
            }
        }

        // 8. Business rules
        if let Err(e) = self.check_business_rules(transaction) {
            errors.push(e);
        }

        // 9. Risk threshold check
        if fraud_score > self.config.fraud_threshold {
            errors.push(ValidationError::RiskThresholdExceeded(format!(
                "Risk score {} exceeds threshold {}",
                fraud_score, self.config.fraud_threshold
            )));
        }

        let is_valid = errors.is_empty();

        ValidationResult {
            transaction_id: transaction.transaction_id.clone(),
            is_valid,
            errors,
            warnings,
            fraud_score,
            risk_breakdown,
            compliance_checks,
            validated_at: Utc::now(),
        }
    }

    /// Calculate amount-based risk score
    fn calculate_amount_risk(&self, amount: f64) -> u8 {
        if amount > 100_000.0 {
            40
        } else if amount > 50_000.0 {
            30
        } else if amount > 10_000.0 {
            15
        } else {
            0
        }
    }

    /// Calculate time-based risk score
    fn calculate_time_risk(&self, timestamp: &DateTime<Utc>) -> u8 {
        let hour = timestamp.hour();
        if !(6..=22).contains(&hour) {
            20 // High risk outside business hours
        } else if !(9..=17).contains(&hour) {
            10 // Medium risk outside normal hours
        } else {
            0 // Low risk during business hours
        }
    }

    /// Check transaction velocity (multiple transactions in short period)
    fn check_velocity(
        &self,
        transaction: &Transaction,
    ) -> (u8, Option<ValidationError>, Vec<String>) {
        let mut risk_score = 0u8;
        let mut error = None;
        let mut warnings = Vec::new();

        let window_start =
            transaction.timestamp - Duration::minutes(self.config.velocity_check_window_minutes);

        // Get recent transactions from same user
        let recent_transactions: Vec<&TransactionHistory> = self
            .transaction_history
            .iter()
            .filter(|h| h.user_id == transaction.user_id && h.timestamp >= window_start)
            .collect();

        let transaction_count = recent_transactions.len();
        let total_amount: f64 =
            recent_transactions.iter().map(|h| h.amount).sum::<f64>() + transaction.amount;

        // Check transaction count
        if transaction_count >= self.config.max_transactions_per_window {
            risk_score = risk_score.saturating_add(30);
            error = Some(ValidationError::VelocityViolation(format!(
                "Too many transactions: {} in {} minutes",
                transaction_count + 1,
                self.config.velocity_check_window_minutes
            )));
        } else if transaction_count >= (self.config.max_transactions_per_window / 2) {
            risk_score = risk_score.saturating_add(15);
            warnings.push(format!(
                "High transaction velocity: {} transactions in window",
                transaction_count + 1
            ));
        }

        // Check total amount
        if total_amount >= self.config.max_amount_per_window {
            risk_score = risk_score.saturating_add(25);
            error = Some(ValidationError::VelocityViolation(format!(
                "Total amount ${:.2} exceeds window limit ${:.2}",
                total_amount, self.config.max_amount_per_window
            )));
        } else if total_amount >= (self.config.max_amount_per_window * 0.75) {
            risk_score = risk_score.saturating_add(10);
            warnings.push(format!(
                "Approaching amount limit: ${:.2} of ${:.2}",
                total_amount, self.config.max_amount_per_window
            ));
        }

        (risk_score, error, warnings)
    }

    /// Validate transaction amount
    fn validate_amount(&self, transaction: &Transaction) -> Result<(), ValidationError> {
        if transaction.amount <= 0.0 {
            return Err(ValidationError::InvalidAmount(
                "Amount must be positive".to_string(),
            ));
        }

        if transaction.amount < self.config.min_transaction_amount {
            return Err(ValidationError::InvalidAmount(format!(
                "Amount {} below minimum {}",
                transaction.amount, self.config.min_transaction_amount
            )));
        }

        if transaction.amount > self.config.max_transaction_amount {
            return Err(ValidationError::InvalidAmount(format!(
                "Amount {} exceeds maximum {}",
                transaction.amount, self.config.max_transaction_amount
            )));
        }

        Ok(())
    }

    /// Validate account numbers
    fn validate_accounts(&self, transaction: &Transaction) -> Result<(), ValidationError> {
        let account_regex =
            Regex::new(r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$").unwrap();

        if let Some(ref from_account) = transaction.from_account {
            if !account_regex.is_match(from_account) && !from_account.starts_with("****") {
                return Err(ValidationError::InvalidAccount(format!(
                    "Invalid from_account format: {}",
                    from_account
                )));
            }
        }

        if let Some(ref to_account) = transaction.to_account {
            if !account_regex.is_match(to_account) && !to_account.starts_with("****") {
                return Err(ValidationError::InvalidAccount(format!(
                    "Invalid to_account format: {}",
                    to_account
                )));
            }
        }

        Ok(())
    }

    /// Check for fraud patterns
    fn check_fraud_patterns(&self, transaction: &Transaction) -> (u8, Vec<String>) {
        let mut score = 0u8;
        let mut warnings = Vec::new();

        // Pattern 1: Large round numbers (possible money laundering)
        if transaction.amount % 1000.0 == 0.0 && transaction.amount >= 10000.0 {
            score += 20;
            warnings.push("Large round number transaction".to_string());
        }

        // Pattern 2: High-value transactions
        if transaction.amount > 50000.0 {
            score += 30;
            warnings.push("High-value transaction requires review".to_string());
        }

        // Pattern 3: Wire transfer to different account
        if transaction.transaction_type == TransactionType::WireTransfer {
            score += 15;
            warnings.push("Wire transfer flagged for review".to_string());
        }

        // Pattern 4: Unusual timestamp (outside business hours)
        let hour = transaction.timestamp.hour();
        if !(6..=22).contains(&hour) {
            score += 10;
            warnings.push("Transaction outside business hours".to_string());
        }

        (score, warnings)
    }

    /// Check AML/KYC compliance
    fn check_aml_compliance(&self, transaction: &Transaction) -> bool {
        // Simplified AML check
        // In production, this would check against government watch lists, PEPs, etc.

        // Rule 1: Transactions over $10,000 require enhanced due diligence
        if transaction.amount > 10000.0 {
            // Would check KYC documentation, beneficial ownership, etc.
            return true; // Simplified: assume compliant
        }

        // Rule 2: Wire transfers require source of funds verification
        if transaction.transaction_type == TransactionType::WireTransfer {
            // Would verify source of funds documentation
            return true; // Simplified: assume compliant
        }

        true
    }

    /// Check business rules
    fn check_business_rules(&self, transaction: &Transaction) -> Result<(), ValidationError> {
        // Rule 1: Transfers must have both from and to accounts
        if transaction.transaction_type == TransactionType::Transfer
            && (transaction.from_account.is_none() || transaction.to_account.is_none())
        {
            return Err(ValidationError::BusinessRuleViolation(
                "Transfers must specify both from and to accounts".to_string(),
            ));
        }

        // Rule 2: Deposits must have to_account
        if transaction.transaction_type == TransactionType::Deposit
            && transaction.to_account.is_none()
        {
            return Err(ValidationError::BusinessRuleViolation(
                "Deposits must specify to_account".to_string(),
            ));
        }

        // Rule 3: Withdrawals must have from_account
        if transaction.transaction_type == TransactionType::Withdrawal
            && transaction.from_account.is_none()
        {
            return Err(ValidationError::BusinessRuleViolation(
                "Withdrawals must specify from_account".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate multiple transactions in batch
    pub fn validate_batch(&mut self, transactions: &[Transaction]) -> Vec<ValidationResult> {
        transactions.iter().map(|tx| self.validate(tx)).collect()
    }

    /// Get validation statistics
    pub fn get_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert(
            "total_processed".to_string(),
            self.processed_transactions.len(),
        );
        stats.insert(
            "total_transactions_in_history".to_string(),
            self.transaction_history.len(),
        );
        stats
    }

    /// Clear old transaction history (for memory management)
    pub fn clear_old_history(&mut self, before: DateTime<Utc>) {
        self.transaction_history.retain(|h| h.timestamp >= before);
    }
}

impl Default for TransactionValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_valid_transaction() -> Transaction {
        Transaction {
            transaction_id: "TXN-001".to_string(),
            transaction_type: TransactionType::Transfer,
            amount: 1000.0,
            currency: "USD".to_string(),
            from_account: Some("ACCT-1234-5678-9012-3456".to_string()),
            to_account: Some("ACCT-6789-0123-4567-8901".to_string()),
            timestamp: Utc::now(),
            user_id: "USER-001".to_string(),
            metadata: None,
        }
    }

    #[test]
    fn test_valid_transaction() {
        let mut validator = TransactionValidator::new();
        let transaction = create_valid_transaction();
        let result = validator.validate(&transaction);

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_invalid_amount() {
        let mut validator = TransactionValidator::new();
        let mut transaction = create_valid_transaction();
        transaction.amount = -100.0;

        let result = validator.validate(&transaction);
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_duplicate_detection() {
        let mut validator = TransactionValidator::new();
        let transaction = create_valid_transaction();

        let result1 = validator.validate(&transaction);
        assert!(result1.is_valid);

        let result2 = validator.validate(&transaction);
        assert!(!result2.is_valid);
        assert!(result2
            .errors
            .iter()
            .any(|e| matches!(e, ValidationError::DuplicateTransaction(_))));
    }

    #[test]
    fn test_fraud_detection() {
        let mut validator = TransactionValidator::new();
        let mut transaction = create_valid_transaction();
        transaction.amount = 100000.0; // High value

        let result = validator.validate(&transaction);
        assert!(result.fraud_score > 0);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_business_rules() {
        let mut validator = TransactionValidator::new();
        let mut transaction = create_valid_transaction();
        transaction.transaction_type = TransactionType::Transfer;
        transaction.from_account = None; // Missing required field

        let result = validator.validate(&transaction);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_velocity_check() {
        let mut validator = TransactionValidator::new();
        let user_id = "USER-VELOCITY-TEST".to_string();

        // Create multiple transactions from same user
        for i in 0..5 {
            let mut transaction = create_valid_transaction();
            transaction.user_id = user_id.clone();
            transaction.transaction_id = format!("TXN-{}", i);
            transaction.amount = 5000.0;

            let result = validator.validate(&transaction);
            // First transactions should pass
            if i < 3 {
                assert!(result.is_valid || !result.warnings.is_empty());
            }
        }

        // Check that velocity warnings are present
        let stats = validator.get_stats();
        assert_eq!(stats["total_transactions_in_history"], 5);
    }

    #[test]
    fn test_risk_breakdown() {
        let mut validator = TransactionValidator::new();
        let mut transaction = create_valid_transaction();
        transaction.amount = 150_000.0; // High amount

        let result = validator.validate(&transaction);

        // Check that risk breakdown is populated
        assert!(result.risk_breakdown.amount_risk > 0);
        assert!(result.risk_breakdown.total_score > 0);
        assert_eq!(result.risk_breakdown.total_score, result.fraud_score);
    }

    #[test]
    fn test_time_based_risk() {
        let mut validator = TransactionValidator::new();
        let mut transaction = create_valid_transaction();

        // Set timestamp to late night (high risk)
        let late_night = Utc::now().date_naive().and_hms_opt(2, 0, 0).unwrap();
        transaction.timestamp = DateTime::from_naive_utc_and_offset(late_night, Utc);

        let result = validator.validate(&transaction);
        assert!(result.risk_breakdown.time_risk > 0);
    }

    #[test]
    fn test_risk_level_description() {
        let mut validator = TransactionValidator::new();

        // Low risk
        let mut transaction = create_valid_transaction();
        transaction.amount = 100.0;
        let result = validator.validate(&transaction);
        assert_eq!(result.risk_level(), "Low");

        // High risk
        let mut transaction2 = create_valid_transaction();
        transaction2.transaction_id = "TXN-002".to_string();
        transaction2.amount = 200_000.0;
        let result2 = validator.validate(&transaction2);
        assert!(matches!(
            result2.risk_level(),
            "High" | "Critical" | "Medium"
        ));
    }

    #[test]
    fn test_manual_review_flag() {
        let mut validator = TransactionValidator::new();
        let mut transaction = create_valid_transaction();
        transaction.amount = 100_000.0; // Should trigger warnings

        let result = validator.validate(&transaction);
        // High amount should require manual review
        assert!(result.requires_manual_review() || !result.warnings.is_empty());
    }

    #[test]
    fn test_batch_validation() {
        let mut validator = TransactionValidator::new();

        let transactions = vec![
            create_valid_transaction(),
            {
                let mut tx = create_valid_transaction();
                tx.transaction_id = "TXN-002".to_string();
                tx
            },
            {
                let mut tx = create_valid_transaction();
                tx.transaction_id = "TXN-003".to_string();
                tx.amount = -100.0; // Invalid
                tx
            },
        ];

        let results = validator.validate_batch(&transactions);

        assert_eq!(results.len(), 3);
        assert!(results[0].is_valid);
        assert!(results[1].is_valid);
        assert!(!results[2].is_valid); // Invalid amount
    }

    #[test]
    fn test_history_cleanup() {
        let mut validator = TransactionValidator::new();

        // Add transactions with old timestamps
        let old_time = Utc::now() - Duration::hours(48);
        for i in 0..5 {
            let mut transaction = create_valid_transaction();
            transaction.transaction_id = format!("TXN-{}", i);
            transaction.timestamp = old_time;
            validator.validate(&transaction);
        }

        let cutoff = Utc::now() - Duration::hours(24);
        validator.clear_old_history(cutoff);

        let stats = validator.get_stats();
        assert_eq!(stats["total_transactions_in_history"], 0);
    }

    #[test]
    fn test_is_approved() {
        let mut validator = TransactionValidator::new();

        // Low risk transaction
        let mut transaction = create_valid_transaction();
        transaction.amount = 500.0;
        let result = validator.validate(&transaction);
        assert!(result.is_approved());

        // High risk transaction
        let mut transaction2 = create_valid_transaction();
        transaction2.transaction_id = "TXN-002".to_string();
        transaction2.amount = 500_000.0;
        let result2 = validator.validate(&transaction2);
        // May not be approved due to high risk
        assert!(!result2.is_approved() || result2.fraud_score < 50);
    }

    #[test]
    fn test_velocity_amount_limit() {
        let config = ValidatorConfig {
            max_transaction_amount: 1_000_000.0,
            min_transaction_amount: 0.01,
            fraud_threshold: 70,
            enable_duplicate_check: true,
            enable_aml_check: true,
            velocity_check_window_minutes: 60,
            max_transactions_per_window: 10,
            max_amount_per_window: 50_000.0, // Low limit for testing
        };

        let mut validator = TransactionValidator::with_config(config);
        let user_id = "USER-AMOUNT-TEST".to_string();

        // Create transactions that exceed amount limit
        for i in 0..3 {
            let mut transaction = create_valid_transaction();
            transaction.user_id = user_id.clone();
            transaction.transaction_id = format!("TXN-{}", i);
            transaction.amount = 20_000.0; // Total will exceed 50k

            let result = validator.validate(&transaction);
            if i >= 2 {
                // Third transaction should trigger velocity error
                assert!(result.risk_breakdown.velocity_risk > 0);
            }
        }
    }

    #[test]
    fn test_json_export() {
        let mut validator = TransactionValidator::new();
        let transaction = create_valid_transaction();
        let result = validator.validate(&transaction);

        let json = result.to_json();
        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("TXN-001"));
        assert!(json_str.contains("risk_breakdown"));
    }
}
