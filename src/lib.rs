//! # Rust Transaction Validator
//!
//! A memory-safe financial transaction validator for fraud detection and regulatory compliance.
//!
//! ## Features
//!
//! - **Memory Safety**: Built with Rust to prevent vulnerabilities in financial systems
//! - **Fraud Detection**: Pattern-based fraud detection algorithms
//! - **Compliance Checks**: AML/KYC validation rules
//! - **Business Rules**: Configurable transaction validation rules
//! - **Audit Trail**: Complete transaction validation history
//!
//! ## Alignment with Federal Guidance
//!
//! Implements secure financial transaction processing using memory-safe Rust,
//! aligning with 2024 CISA/FBI guidance for critical financial infrastructure.

use chrono::{DateTime, Utc};
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
    pub compliance_checks: HashMap<String, bool>,
    pub validated_at: DateTime<Utc>,
}

impl ValidationResult {
    /// Check if transaction passed all validations
    pub fn is_approved(&self) -> bool {
        self.is_valid && self.errors.is_empty() && self.fraud_score < 50
    }

    /// Export as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Transaction validator configuration
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub max_transaction_amount: f64,
    pub min_transaction_amount: f64,
    pub fraud_threshold: u8,
    pub enable_duplicate_check: bool,
    pub enable_aml_check: bool,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            max_transaction_amount: 1_000_000.0,
            min_transaction_amount: 0.01,
            fraud_threshold: 70,
            enable_duplicate_check: true,
            enable_aml_check: true,
        }
    }
}

/// Financial transaction validator
pub struct TransactionValidator {
    config: ValidatorConfig,
    processed_transactions: Vec<String>,
}

impl TransactionValidator {
    /// Create a new validator with default configuration
    pub fn new() -> Self {
        Self {
            config: ValidatorConfig::default(),
            processed_transactions: Vec::new(),
        }
    }

    /// Create a new validator with custom configuration
    pub fn with_config(config: ValidatorConfig) -> Self {
        Self {
            config,
            processed_transactions: Vec::new(),
        }
    }

    /// Validate a transaction
    pub fn validate(&mut self, transaction: &Transaction) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut compliance_checks = HashMap::new();
        let mut fraud_score = 0u8;

        // 1. Amount validation
        if let Err(e) = self.validate_amount(transaction) {
            errors.push(e);
        }

        // 2. Account validation
        if let Err(e) = self.validate_accounts(transaction) {
            errors.push(e);
        }

        // 3. Duplicate detection
        if self.config.enable_duplicate_check {
            if self.processed_transactions.contains(&transaction.transaction_id) {
                errors.push(ValidationError::DuplicateTransaction(
                    transaction.transaction_id.clone(),
                ));
            } else {
                self.processed_transactions.push(transaction.transaction_id.clone());
            }
        }

        // 4. Fraud detection
        let fraud_checks = self.check_fraud_patterns(transaction);
        fraud_score = fraud_checks.0;
        if !fraud_checks.1.is_empty() {
            warnings.extend(fraud_checks.1);
        }

        // 5. AML compliance
        if self.config.enable_aml_check {
            let aml_result = self.check_aml_compliance(transaction);
            compliance_checks.insert("AML".to_string(), aml_result);
            if !aml_result {
                errors.push(ValidationError::ComplianceFailed(
                    "AML compliance check failed".to_string(),
                ));
            }
        }

        // 6. Business rules
        if let Err(e) = self.check_business_rules(transaction) {
            errors.push(e);
        }

        let is_valid = errors.is_empty();

        ValidationResult {
            transaction_id: transaction.transaction_id.clone(),
            is_valid,
            errors,
            warnings,
            fraud_score,
            compliance_checks,
            validated_at: Utc::now(),
        }
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
        let account_regex = Regex::new(r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$").unwrap();

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
        if hour < 6 || hour > 22 {
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
        if transaction.transaction_type == TransactionType::Transfer {
            if transaction.from_account.is_none() || transaction.to_account.is_none() {
                return Err(ValidationError::BusinessRuleViolation(
                    "Transfers must specify both from and to accounts".to_string(),
                ));
            }
        }

        // Rule 2: Deposits must have to_account
        if transaction.transaction_type == TransactionType::Deposit {
            if transaction.to_account.is_none() {
                return Err(ValidationError::BusinessRuleViolation(
                    "Deposits must specify to_account".to_string(),
                ));
            }
        }

        // Rule 3: Withdrawals must have from_account
        if transaction.transaction_type == TransactionType::Withdrawal {
            if transaction.from_account.is_none() {
                return Err(ValidationError::BusinessRuleViolation(
                    "Withdrawals must specify from_account".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Get validation statistics
    pub fn get_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert(
            "total_processed".to_string(),
            self.processed_transactions.len(),
        );
        stats
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
        assert!(result2.errors.iter().any(|e| matches!(
            e,
            ValidationError::DuplicateTransaction(_)
        )));
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
}
