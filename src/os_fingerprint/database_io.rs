//! OS Fingerprint Database I/O
//!
//! This module provides JSON/YAML import/export functionality for OS fingerprint databases.
//! Allows loading custom signatures and saving fingerprint collections.

use crate::error::{ScanResult, ScanError};
use super::fingerprint_db::{OsFingerprintDatabase, OsSignature, OsFamily};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

/// Fingerprint database file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintDatabaseFile {
    /// Database metadata
    pub metadata: DatabaseMetadata,
    /// OS signatures
    pub signatures: Vec<OsSignature>,
}

/// Database metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseMetadata {
    /// Database name
    pub name: String,
    /// Database version
    pub version: String,
    /// Creation date
    pub created: String,
    /// Last modified date
    pub modified: String,
    /// Number of signatures
    pub signature_count: usize,
    /// Description
    pub description: Option<String>,
    /// Author/source
    pub author: Option<String>,
}

/// Database I/O operations
pub struct DatabaseIO;

impl DatabaseIO {
    /// Export database to JSON file
    pub fn export_to_json<P: AsRef<Path>>(
        database: &OsFingerprintDatabase,
        path: P,
        pretty: bool,
    ) -> ScanResult<()> {
        info!("Exporting fingerprint database to JSON: {:?}", path.as_ref());
        
        let signatures: Vec<OsSignature> = database.signatures().values().cloned().collect();
        
        let db_file = FingerprintDatabaseFile {
            metadata: DatabaseMetadata {
                name: "NrMAP OS Fingerprint Database".to_string(),
                version: "1.0.0".to_string(),
                created: chrono::Utc::now().to_rfc3339(),
                modified: chrono::Utc::now().to_rfc3339(),
                signature_count: signatures.len(),
                description: Some("Comprehensive OS fingerprint signature database".to_string()),
                author: Some("NrMAP Project".to_string()),
            },
            signatures,
        };
        
        let json = if pretty {
            serde_json::to_string_pretty(&db_file)
                .map_err(|e| ScanError::ScannerError { message: format!("JSON serialization failed: {}", e) })?
        } else {
            serde_json::to_string(&db_file)
                .map_err(|e| ScanError::ScannerError { message: format!("JSON serialization failed: {}", e) })?
        };
        
        fs::write(path.as_ref(), json)
            .map_err(|e| ScanError::Io(e))?;
        
        info!("Successfully exported {} signatures to JSON", db_file.metadata.signature_count);
        Ok(())
    }

    /// Import database from JSON file
    pub fn import_from_json<P: AsRef<Path>>(path: P) -> ScanResult<OsFingerprintDatabase> {
        info!("Importing fingerprint database from JSON: {:?}", path.as_ref());
        
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| ScanError::Io(e))?;
        
        let db_file: FingerprintDatabaseFile = serde_json::from_str(&content)
            .map_err(|e| ScanError::ScannerError { message: format!("JSON parsing failed: {}", e) })?;
        
        debug!("Loaded database metadata: {} v{}", db_file.metadata.name, db_file.metadata.version);
        debug!("Signatures: {}", db_file.metadata.signature_count);
        
        let mut database = OsFingerprintDatabase::empty();
        
        for signature in db_file.signatures {
            database.add_signature(signature);
        }
        
        info!("Successfully imported {} signatures from JSON", database.signature_count());
        Ok(database)
    }

    /// Export database to YAML file
    pub fn export_to_yaml<P: AsRef<Path>>(
        database: &OsFingerprintDatabase,
        path: P,
    ) -> ScanResult<()> {
        info!("Exporting fingerprint database to YAML: {:?}", path.as_ref());
        
        let signatures: Vec<OsSignature> = database.signatures().values().cloned().collect();
        
        let db_file = FingerprintDatabaseFile {
            metadata: DatabaseMetadata {
                name: "NrMAP OS Fingerprint Database".to_string(),
                version: "1.0.0".to_string(),
                created: chrono::Utc::now().to_rfc3339(),
                modified: chrono::Utc::now().to_rfc3339(),
                signature_count: signatures.len(),
                description: Some("Comprehensive OS fingerprint signature database".to_string()),
                author: Some("NrMAP Project".to_string()),
            },
            signatures,
        };
        
        let yaml = serde_yaml::to_string(&db_file)
            .map_err(|e| ScanError::ScannerError { message: format!("YAML serialization failed: {}", e) })?;
        
        fs::write(path.as_ref(), yaml)
            .map_err(|e| ScanError::Io(e))?;
        
        info!("Successfully exported {} signatures to YAML", db_file.metadata.signature_count);
        Ok(())
    }

    /// Import database from YAML file
    pub fn import_from_yaml<P: AsRef<Path>>(path: P) -> ScanResult<OsFingerprintDatabase> {
        info!("Importing fingerprint database from YAML: {:?}", path.as_ref());
        
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| ScanError::Io(e))?;
        
        let db_file: FingerprintDatabaseFile = serde_yaml::from_str(&content)
            .map_err(|e| ScanError::ScannerError { message: format!("YAML parsing failed: {}", e) })?;
        
        debug!("Loaded database metadata: {} v{}", db_file.metadata.name, db_file.metadata.version);
        debug!("Signatures: {}", db_file.metadata.signature_count);
        
        let mut database = OsFingerprintDatabase::empty();
        
        for signature in db_file.signatures {
            database.add_signature(signature);
        }
        
        info!("Successfully imported {} signatures from YAML", database.signature_count());
        Ok(database)
    }

    /// Auto-detect format and import
    pub fn import_auto<P: AsRef<Path>>(path: P) -> ScanResult<OsFingerprintDatabase> {
        let path_ref = path.as_ref();
        
        if let Some(ext) = path_ref.extension() {
            match ext.to_str() {
                Some("json") => Self::import_from_json(path),
                Some("yaml") | Some("yml") => Self::import_from_yaml(path),
                _ => Err(ScanError::ScannerError {
                    message: format!("Unsupported file extension: {:?}", ext),
                }),
            }
        } else {
            Err(ScanError::ScannerError {
                message: "No file extension found".to_string(),
            })
        }
    }

    /// Merge multiple databases
    pub fn merge_databases(databases: Vec<OsFingerprintDatabase>) -> OsFingerprintDatabase {
        info!("Merging {} databases", databases.len());
        
        let mut merged = OsFingerprintDatabase::empty();
        let mut total_added = 0;
        
        for db in databases {
            for signature in db.signatures().values() {
                merged.add_signature(signature.clone());
                total_added += 1;
            }
        }
        
        info!("Merged {} total signatures", total_added);
        merged
    }

    /// Export single signature to JSON
    pub fn export_signature_json(signature: &OsSignature, pretty: bool) -> ScanResult<String> {
        if pretty {
            serde_json::to_string_pretty(signature)
                .map_err(|e| ScanError::ScannerError { message: format!("JSON serialization failed: {}", e) })
        } else {
            serde_json::to_string(signature)
                .map_err(|e| ScanError::ScannerError { message: format!("JSON serialization failed: {}", e) })
        }
    }

    /// Export single signature to YAML
    pub fn export_signature_yaml(signature: &OsSignature) -> ScanResult<String> {
        serde_yaml::to_string(signature)
            .map_err(|e| ScanError::ScannerError { message: format!("YAML serialization failed: {}", e) })
    }

    /// Import single signature from JSON
    pub fn import_signature_json(json: &str) -> ScanResult<OsSignature> {
        serde_json::from_str(json)
            .map_err(|e| ScanError::ScannerError { message: format!("JSON parsing failed: {}", e) })
    }

    /// Import single signature from YAML
    pub fn import_signature_yaml(yaml: &str) -> ScanResult<OsSignature> {
        serde_yaml::from_str(yaml)
            .map_err(|e| ScanError::ScannerError { message: format!("YAML parsing failed: {}", e) })
    }

    /// Validate database integrity
    pub fn validate_database(database: &OsFingerprintDatabase) -> ScanResult<ValidationReport> {
        info!("Validating fingerprint database");
        
        let mut report = ValidationReport {
            total_signatures: database.signature_count(),
            valid_signatures: 0,
            invalid_signatures: 0,
            issues: Vec::new(),
        };
        
        for (id, signature) in database.signatures() {
            let mut signature_valid = true;
            
            // Check OS name
            if signature.os_name.is_empty() {
                report.issues.push(format!("Signature {}: Empty OS name", id));
                signature_valid = false;
            }
            
            // Check confidence weight
            if signature.confidence_weight < 0.0 || signature.confidence_weight > 1.0 {
                report.issues.push(format!("Signature {}: Invalid confidence weight: {}", 
                                          id, signature.confidence_weight));
                signature_valid = false;
            }
            
            // Check TCP signature if present
            if let Some(ref tcp_sig) = signature.tcp_signature {
                if tcp_sig.ttl_range.0 > tcp_sig.ttl_range.1 {
                    report.issues.push(format!("Signature {}: Invalid TTL range", id));
                    signature_valid = false;
                }
                if tcp_sig.window_size_range.0 > tcp_sig.window_size_range.1 {
                    report.issues.push(format!("Signature {}: Invalid window size range", id));
                    signature_valid = false;
                }
            }
            
            if signature_valid {
                report.valid_signatures += 1;
            } else {
                report.invalid_signatures += 1;
            }
        }
        
        if report.invalid_signatures > 0 {
            warn!("Database validation found {} issues", report.invalid_signatures);
        } else {
            info!("Database validation passed: all {} signatures valid", report.valid_signatures);
        }
        
        Ok(report)
    }
}

/// Database validation report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub total_signatures: usize,
    pub valid_signatures: usize,
    pub invalid_signatures: usize,
    pub issues: Vec<String>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        self.invalid_signatures == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_export_import_json() {
        let db = OsFingerprintDatabase::new();
        let temp_file = NamedTempFile::new().unwrap();
        
        // Export
        let result = DatabaseIO::export_to_json(&db, temp_file.path(), true);
        assert!(result.is_ok());
        
        // Import
        let imported = DatabaseIO::import_from_json(temp_file.path());
        assert!(imported.is_ok());
        
        let imported_db = imported.unwrap();
        assert!(imported_db.signature_count() > 0);
    }

    #[test]
    fn test_export_import_yaml() {
        let db = OsFingerprintDatabase::new();
        let temp_file = NamedTempFile::new().unwrap();
        
        // Export
        let result = DatabaseIO::export_to_yaml(&db, temp_file.path());
        assert!(result.is_ok());
        
        // Import
        let imported = DatabaseIO::import_from_yaml(temp_file.path());
        assert!(imported.is_ok());
        
        let imported_db = imported.unwrap();
        assert!(imported_db.signature_count() > 0);
    }

    #[test]
    fn test_validate_database() {
        let db = OsFingerprintDatabase::new();
        let report = DatabaseIO::validate_database(&db);
        
        assert!(report.is_ok());
        let validation = report.unwrap();
        assert!(validation.is_valid());
    }

    #[test]
    fn test_merge_databases() {
        let db1 = OsFingerprintDatabase::new();
        let db2 = OsFingerprintDatabase::new();
        
        let merged = DatabaseIO::merge_databases(vec![db1, db2]);
        assert!(merged.signature_count() > 0);
    }
}

