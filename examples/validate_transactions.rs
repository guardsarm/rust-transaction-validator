//! Transaction validation example
//!
//! This example demonstrates financial transaction validation including
//! fraud detection, compliance checks, and business rule enforcement.

use chrono::Utc;
use rust_transaction_validator::{
    Transaction, TransactionType, TransactionValidator, ValidatorConfig,
};
use std::collections::HashMap;

fn main() {
    println!("=== Financial Transaction Validator ===\n");

    // Create validator with default configuration
    let mut validator = TransactionValidator::new();

    // Example 1: Valid wire transfer
    println!("1. Validating Wire Transfer");
    let wire_transfer = Transaction {
        transaction_id: "TXN-2024-11-06-001".to_string(),
        transaction_type: TransactionType::WireTransfer,
        amount: 50000.0,
        currency: "USD".to_string(),
        from_account: Some("ACCT-1234-5678-9012-3456".to_string()),
        to_account: Some("ACCT-6789-0123-4567-8901".to_string()),
        timestamp: Utc::now(),
        user_id: "USER-12345".to_string(),
        metadata: Some(HashMap::from([
            (
                "beneficiary_name".to_string(),
                "Corporate Account".to_string(),
            ),
            ("purpose".to_string(), "Business payment".to_string()),
        ])),
    };

    let result = validator.validate(&wire_transfer);
    println!("   Transaction ID: {}", result.transaction_id);
    println!("   Valid: {}", result.is_valid);
    println!("   Approved: {}", result.is_approved());
    println!("   Fraud Score: {}/100", result.fraud_score);
    println!("   Warnings: {:?}", result.warnings);
    println!("   Errors: {:?}", result.errors);
    println!();

    // Example 2: Invalid transaction (negative amount)
    println!("2. Validating Invalid Transaction (Negative Amount)");
    let invalid_transaction = Transaction {
        transaction_id: "TXN-2024-11-06-002".to_string(),
        transaction_type: TransactionType::Payment,
        amount: -1000.0, // Invalid!
        currency: "USD".to_string(),
        from_account: Some("ACCT-1111-2222-3333-4444".to_string()),
        to_account: Some("ACCT-5555-6666-7777-8888".to_string()),
        timestamp: Utc::now(),
        user_id: "USER-67890".to_string(),
        metadata: None,
    };

    let result = validator.validate(&invalid_transaction);
    println!("   Transaction ID: {}", result.transaction_id);
    println!("   Valid: {}", result.is_valid);
    println!("   Errors: {:?}", result.errors);
    println!();

    // Example 3: Duplicate transaction detection
    println!("3. Duplicate Transaction Detection");
    let transaction1 = Transaction {
        transaction_id: "TXN-DUPLICATE-001".to_string(),
        transaction_type: TransactionType::Transfer,
        amount: 5000.0,
        currency: "USD".to_string(),
        from_account: Some("ACCT-1234-5678-9012-3456".to_string()),
        to_account: Some("ACCT-9999-8888-7777-6666".to_string()),
        timestamp: Utc::now(),
        user_id: "USER-11111".to_string(),
        metadata: None,
    };

    println!("   First submission:");
    let result1 = validator.validate(&transaction1);
    println!("     Valid: {}", result1.is_valid);

    println!("   Second submission (duplicate):");
    let result2 = validator.validate(&transaction1);
    println!("     Valid: {}", result2.is_valid);
    println!("     Errors: {:?}", result2.errors);
    println!();

    // Example 4: High-value transaction (fraud detection)
    println!("4. High-Value Transaction (Fraud Detection)");
    let high_value = Transaction {
        transaction_id: "TXN-2024-11-06-003".to_string(),
        transaction_type: TransactionType::WireTransfer,
        amount: 100000.0, // High value triggers fraud check
        currency: "USD".to_string(),
        from_account: Some("ACCT-1234-5678-9012-3456".to_string()),
        to_account: Some("ACCT-7777-8888-9999-0000".to_string()),
        timestamp: Utc::now(),
        user_id: "USER-22222".to_string(),
        metadata: None,
    };

    let result = validator.validate(&high_value);
    println!("   Transaction ID: {}", result.transaction_id);
    println!("   Fraud Score: {}/100", result.fraud_score);
    println!("   Warnings: {:?}", result.warnings);
    println!("   Approved: {}", result.is_approved());
    println!();

    // Example 5: Business rule violation
    println!("5. Business Rule Violation");
    let invalid_transfer = Transaction {
        transaction_id: "TXN-2024-11-06-004".to_string(),
        transaction_type: TransactionType::Transfer,
        amount: 2000.0,
        currency: "USD".to_string(),
        from_account: Some("ACCT-1234-5678-9012-3456".to_string()),
        to_account: None, // Missing required to_account!
        timestamp: Utc::now(),
        user_id: "USER-33333".to_string(),
        metadata: None,
    };

    let result = validator.validate(&invalid_transfer);
    println!("   Transaction ID: {}", result.transaction_id);
    println!("   Valid: {}", result.is_valid);
    println!("   Errors: {:?}", result.errors);
    println!();

    // Example 6: Multiple valid transactions
    println!("6. Processing Multiple Transactions");
    let transactions = vec![
        Transaction {
            transaction_id: "TXN-BATCH-001".to_string(),
            transaction_type: TransactionType::Deposit,
            amount: 1000.0,
            currency: "USD".to_string(),
            from_account: None,
            to_account: Some("ACCT-1234-5678-9012-3456".to_string()),
            timestamp: Utc::now(),
            user_id: "USER-44444".to_string(),
            metadata: None,
        },
        Transaction {
            transaction_id: "TXN-BATCH-002".to_string(),
            transaction_type: TransactionType::Withdrawal,
            amount: 500.0,
            currency: "USD".to_string(),
            from_account: Some("ACCT-1234-5678-9012-3456".to_string()),
            to_account: None,
            timestamp: Utc::now(),
            user_id: "USER-44444".to_string(),
            metadata: None,
        },
        Transaction {
            transaction_id: "TXN-BATCH-003".to_string(),
            transaction_type: TransactionType::Payment,
            amount: 250.0,
            currency: "USD".to_string(),
            from_account: Some("ACCT-1234-5678-9012-3456".to_string()),
            to_account: Some("****5678".to_string()), // Masked account
            timestamp: Utc::now(),
            user_id: "USER-44444".to_string(),
            metadata: None,
        },
    ];

    let mut approved = 0;
    let mut rejected = 0;

    for transaction in transactions {
        let result = validator.validate(&transaction);
        if result.is_approved() {
            approved += 1;
            println!("   ✓ {} - Approved", transaction.transaction_id);
        } else {
            rejected += 1;
            println!(
                "   ✗ {} - Rejected: {:?}",
                transaction.transaction_id, result.errors
            );
        }
    }

    println!("\n   Summary: {} approved, {} rejected", approved, rejected);
    println!();

    // Example 7: Custom configuration
    println!("7. Custom Validator Configuration");
    let custom_config = ValidatorConfig {
        max_transaction_amount: 250_000.0,
        min_transaction_amount: 10.0,
        fraud_threshold: 90,
        enable_duplicate_check: true,
        enable_aml_check: true,
        velocity_check_window_minutes: 60,
        max_transactions_per_window: 10,
        max_amount_per_window: 100_000.0,
    };

    let mut custom_validator = TransactionValidator::with_config(custom_config);

    let large_transaction = Transaction {
        transaction_id: "TXN-CUSTOM-001".to_string(),
        transaction_type: TransactionType::WireTransfer,
        amount: 200_000.0,
        currency: "USD".to_string(),
        from_account: Some("ACCT-1234-5678-9012-3456".to_string()),
        to_account: Some("ACCT-9999-8888-7777-6666".to_string()),
        timestamp: Utc::now(),
        user_id: "USER-55555".to_string(),
        metadata: None,
    };

    let result = custom_validator.validate(&large_transaction);
    println!("   Custom validator result:");
    println!("     Approved: {}", result.is_approved());
    println!("     Fraud Score: {}/100", result.fraud_score);
    println!();

    // Statistics
    println!("=== Validator Statistics ===");
    let stats = validator.get_stats();
    for (key, value) in stats {
        println!("   {}: {}", key, value);
    }

    println!("\n=== Security Features ===");
    println!("✓ Memory-safe transaction processing");
    println!("✓ Fraud detection with configurable thresholds");
    println!("✓ AML/KYC compliance checks");
    println!("✓ Business rule enforcement");
    println!("✓ Duplicate transaction prevention");
    println!("✓ Audit trail with complete validation history");

    println!("\n=== Compliance Use Cases ===");
    println!("✓ Bank Secrecy Act (BSA) - AML monitoring");
    println!("✓ FinCEN regulations - Suspicious activity reporting");
    println!("✓ PCI-DSS - Payment transaction security");
    println!("✓ SOX - Financial transaction controls");
    println!("✓ GLBA - Financial privacy requirements");
}
