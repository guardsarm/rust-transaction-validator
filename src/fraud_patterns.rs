//! Advanced fraud detection patterns

use crate::Transaction;
use std::collections::HashMap;

/// Fraud pattern detector
pub struct FraudDetector {
    /// Transaction history for velocity checks
    history: HashMap<String, Vec<Transaction>>,
    /// High-risk countries
    high_risk_countries: Vec<String>,
    /// Suspicious amount thresholds
    thresholds: FraudThresholds,
}

/// Fraud detection thresholds
#[derive(Debug, Clone)]
pub struct FraudThresholds {
    /// Maximum transaction amount (USD)
    pub max_amount: f64,
    /// Maximum transactions per hour
    pub max_transactions_per_hour: usize,
    /// Maximum total amount per day
    pub max_daily_total: f64,
    /// Suspicious round amount threshold
    pub round_amount_threshold: f64,
}

impl Default for FraudThresholds {
    fn default() -> Self {
        Self {
            max_amount: 50000.0,
            max_transactions_per_hour: 10,
            max_daily_total: 100000.0,
            round_amount_threshold: 10000.0,
        }
    }
}

/// Fraud risk score (0-100)
#[derive(Debug, Clone)]
pub struct FraudScore {
    pub score: u8,
    pub risk_level: RiskLevel,
    pub flags: Vec<FraudFlag>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    Low,      // 0-25
    Medium,   // 26-50
    High,     // 51-75
    Critical, // 76-100
}

#[derive(Debug, Clone)]
pub struct FraudFlag {
    pub flag_type: FraudFlagType,
    pub description: String,
    pub severity: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FraudFlagType {
    VelocityExceeded,
    UnusualAmount,
    RoundAmount,
    HighRiskCountry,
    DuplicateTransaction,
    RapidSuccession,
    AmountProgression,
    TimeAnomaly,
    GeographicAnomaly,
}

impl FraudDetector {
    /// Create new fraud detector
    pub fn new() -> Self {
        Self {
            history: HashMap::new(),
            high_risk_countries: vec![
                "KP".to_string(), // North Korea
                "IR".to_string(), // Iran
                "SY".to_string(), // Syria
            ],
            thresholds: FraudThresholds::default(),
        }
    }

    /// Create with custom thresholds
    pub fn with_thresholds(thresholds: FraudThresholds) -> Self {
        let mut detector = Self::new();
        detector.thresholds = thresholds;
        detector
    }

    /// Calculate fraud score for transaction
    pub fn calculate_fraud_score(&mut self, transaction: &Transaction) -> FraudScore {
        let mut score = 0u8;
        let mut flags = Vec::new();

        // Check velocity (transactions per hour)
        if let Some(velocity_flag) = self.check_velocity(transaction) {
            score += velocity_flag.severity;
            flags.push(velocity_flag);
        }

        // Check unusual amounts
        if let Some(amount_flag) = self.check_unusual_amount(transaction) {
            score += amount_flag.severity;
            flags.push(amount_flag);
        }

        // Check round amounts (potential structuring)
        if let Some(round_flag) = self.check_round_amount(transaction) {
            score += round_flag.severity;
            flags.push(round_flag);
        }

        // Check high-risk countries
        if let Some(country_flag) = self.check_high_risk_country(transaction) {
            score += country_flag.severity;
            flags.push(country_flag);
        }

        // Check rapid succession
        if let Some(rapid_flag) = self.check_rapid_succession(transaction) {
            score += rapid_flag.severity;
            flags.push(rapid_flag);
        }

        // Check amount progression (potential testing)
        if let Some(progression_flag) = self.check_amount_progression(transaction) {
            score += progression_flag.severity;
            flags.push(progression_flag);
        }

        // Determine risk level
        let risk_level = match score {
            0..=25 => RiskLevel::Low,
            26..=50 => RiskLevel::Medium,
            51..=75 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        // Add to history
        self.add_to_history(transaction.clone());

        FraudScore {
            score: score.min(100),
            risk_level,
            flags,
        }
    }

    fn check_velocity(&self, transaction: &Transaction) -> Option<FraudFlag> {
        let account = transaction.from_account.as_ref()?;
        if let Some(history) = self.history.get(account) {
            let one_hour_ago = transaction.timestamp - chrono::Duration::hours(1);
            let recent = history
                .iter()
                .filter(|t| t.timestamp > one_hour_ago)
                .count();

            if recent >= self.thresholds.max_transactions_per_hour {
                return Some(FraudFlag {
                    flag_type: FraudFlagType::VelocityExceeded,
                    description: format!(
                        "{} transactions in last hour (limit: {})",
                        recent, self.thresholds.max_transactions_per_hour
                    ),
                    severity: 25,
                });
            }
        }
        None
    }

    fn check_unusual_amount(&self, transaction: &Transaction) -> Option<FraudFlag> {
        if transaction.amount > self.thresholds.max_amount {
            return Some(FraudFlag {
                flag_type: FraudFlagType::UnusualAmount,
                description: format!(
                    "Amount {} exceeds threshold {}",
                    transaction.amount, self.thresholds.max_amount
                ),
                severity: 30,
            });
        }

        // Check against historical average
        if let Some(account) = &transaction.from_account {
            if let Some(history) = self.history.get(account) {
                if !history.is_empty() {
                    let avg: f64 =
                        history.iter().map(|t| t.amount).sum::<f64>() / history.len() as f64;
                    if transaction.amount > avg * 5.0 {
                        return Some(FraudFlag {
                            flag_type: FraudFlagType::UnusualAmount,
                            description: format!(
                                "Amount {} is 5x higher than average {}",
                                transaction.amount, avg
                            ),
                            severity: 20,
                        });
                    }
                }
            }
        }
        None
    }

    fn check_round_amount(&self, transaction: &Transaction) -> Option<FraudFlag> {
        if transaction.amount >= self.thresholds.round_amount_threshold
            && transaction.amount % 1000.0 == 0.0
        {
            return Some(FraudFlag {
                flag_type: FraudFlagType::RoundAmount,
                description: format!(
                    "Suspicious round amount: {} (potential structuring)",
                    transaction.amount
                ),
                severity: 15,
            });
        }
        None
    }

    fn check_high_risk_country(&self, transaction: &Transaction) -> Option<FraudFlag> {
        if let Some(ref metadata) = transaction.metadata {
            if let Some(country) = metadata.get("country") {
                if self.high_risk_countries.contains(country) {
                    return Some(FraudFlag {
                        flag_type: FraudFlagType::HighRiskCountry,
                        description: format!("Transaction from high-risk country: {}", country),
                        severity: 35,
                    });
                }
            }
        }
        None
    }

    fn check_rapid_succession(&self, transaction: &Transaction) -> Option<FraudFlag> {
        if let Some(account) = &transaction.from_account {
            if let Some(history) = self.history.get(account) {
                if let Some(last) = history.last() {
                    let time_diff = transaction.timestamp - last.timestamp;
                    if time_diff < chrono::Duration::seconds(30) {
                        return Some(FraudFlag {
                            flag_type: FraudFlagType::RapidSuccession,
                            description: format!(
                                "Transaction within {} seconds of previous",
                                time_diff.num_seconds()
                            ),
                            severity: 10,
                        });
                    }
                }
            }
        }
        None
    }

    fn check_amount_progression(&self, transaction: &Transaction) -> Option<FraudFlag> {
        if let Some(account) = &transaction.from_account {
            if let Some(history) = self.history.get(account) {
                if history.len() >= 3 {
                    let last_three: Vec<f64> =
                        history.iter().rev().take(3).map(|t| t.amount).collect();
                    // Check if amounts are incrementing (potential testing pattern)
                    if last_three.windows(2).all(|w| w[0] < w[1]) {
                        return Some(FraudFlag {
                            flag_type: FraudFlagType::AmountProgression,
                            description:
                                "Incrementing amounts detected (potential account testing)"
                                    .to_string(),
                            severity: 20,
                        });
                    }
                }
            }
        }
        None
    }

    fn add_to_history(&mut self, transaction: Transaction) {
        if let Some(account) = transaction.from_account.clone() {
            self.history.entry(account).or_default().push(transaction);
        }
    }

    /// Clear old history (keep last 24 hours)
    pub fn cleanup_history(&mut self) {
        let now = chrono::Utc::now();
        let cutoff = now - chrono::Duration::hours(24);

        for transactions in self.history.values_mut() {
            transactions.retain(|t| t.timestamp > cutoff);
        }

        // Remove empty entries
        self.history.retain(|_, v| !v.is_empty());
    }

    /// Get transaction count for account
    pub fn get_transaction_count(&self, account: &str) -> usize {
        self.history.get(account).map_or(0, |h| h.len())
    }

    /// Get daily total for account
    pub fn get_daily_total(&self, account: &str) -> f64 {
        if let Some(history) = self.history.get(account) {
            let one_day_ago = chrono::Utc::now() - chrono::Duration::hours(24);
            history
                .iter()
                .filter(|t| t.timestamp > one_day_ago)
                .map(|t| t.amount)
                .sum()
        } else {
            0.0
        }
    }
}

impl Default for FraudDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_transaction(amount: f64) -> Transaction {
        Transaction {
            transaction_id: "TXN-001".to_string(),
            from_account: Some("ACC-123".to_string()),
            to_account: Some("ACC-456".to_string()),
            amount,
            currency: "USD".to_string(),
            timestamp: Utc::now(),
            transaction_type: crate::TransactionType::Transfer,
            user_id: "USER-001".to_string(),
            metadata: None,
        }
    }

    #[test]
    fn test_low_risk_transaction() {
        let mut detector = FraudDetector::new();
        let txn = create_test_transaction(100.0);
        let score = detector.calculate_fraud_score(&txn);

        assert_eq!(score.risk_level, RiskLevel::Low);
        assert!(score.flags.is_empty());
    }

    #[test]
    fn test_high_amount_detection() {
        let mut detector = FraudDetector::new();
        let txn = create_test_transaction(60000.0);
        let score = detector.calculate_fraud_score(&txn);

        assert!(score.score > 0);
        assert!(score
            .flags
            .iter()
            .any(|f| f.flag_type == FraudFlagType::UnusualAmount));
    }

    #[test]
    fn test_round_amount_detection() {
        let mut detector = FraudDetector::new();
        let txn = create_test_transaction(15000.0);
        let score = detector.calculate_fraud_score(&txn);

        assert!(score
            .flags
            .iter()
            .any(|f| f.flag_type == FraudFlagType::RoundAmount));
    }

    #[test]
    fn test_velocity_detection() {
        let mut detector = FraudDetector::with_thresholds(FraudThresholds {
            max_transactions_per_hour: 2,
            ..Default::default()
        });

        // First transaction - should pass
        let mut txn1 = create_test_transaction(100.0);
        txn1.transaction_id = "TXN-VEL-001".to_string();
        let score1 = detector.calculate_fraud_score(&txn1);
        assert!(score1
            .flags
            .iter()
            .all(|f| f.flag_type != FraudFlagType::VelocityExceeded));

        // Second transaction - should pass (at limit but not exceeded)
        let mut txn2 = create_test_transaction(100.0);
        txn2.transaction_id = "TXN-VEL-002".to_string();
        let score2 = detector.calculate_fraud_score(&txn2);
        assert!(score2
            .flags
            .iter()
            .all(|f| f.flag_type != FraudFlagType::VelocityExceeded));

        // Third transaction - should trigger velocity flag (exceeds limit of 2)
        let mut txn3 = create_test_transaction(100.0);
        txn3.transaction_id = "TXN-VEL-003".to_string();
        let score3 = detector.calculate_fraud_score(&txn3);
        assert!(score3
            .flags
            .iter()
            .any(|f| f.flag_type == FraudFlagType::VelocityExceeded));
    }

    #[test]
    fn test_high_risk_country() {
        let mut detector = FraudDetector::new();
        let mut txn = create_test_transaction(1000.0);
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("country".to_string(), "IR".to_string());
        txn.metadata = Some(metadata);

        let score = detector.calculate_fraud_score(&txn);
        assert!(score
            .flags
            .iter()
            .any(|f| f.flag_type == FraudFlagType::HighRiskCountry));
    }

    #[test]
    fn test_history_cleanup() {
        let mut detector = FraudDetector::new();
        for _ in 0..10 {
            let txn = create_test_transaction(100.0);
            detector.calculate_fraud_score(&txn);
        }

        assert_eq!(detector.get_transaction_count("ACC-123"), 10);
        detector.cleanup_history();
        // Should still have transactions (they're recent)
        assert!(detector.get_transaction_count("ACC-123") > 0);
    }

    #[test]
    fn test_daily_total() {
        let mut detector = FraudDetector::new();
        detector.calculate_fraud_score(&create_test_transaction(1000.0));
        detector.calculate_fraud_score(&create_test_transaction(2000.0));
        detector.calculate_fraud_score(&create_test_transaction(1500.0));

        let total = detector.get_daily_total("ACC-123");
        assert_eq!(total, 4500.0);
    }
}
