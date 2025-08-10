"""
Storage management for vault.sh
Handles vault file operations and data persistence
"""

import os
import json
import time
import shutil
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime

from crypto_utils import VaultCrypto, CryptoError
from config import (
    DEFAULT_VAULT_PATH, DEFAULT_CONFIG_PATH, 
    BACKUP_EXTENSION, EXPORT_EXTENSION
)


class StorageError(Exception):
    """Custom exception for storage operations"""
    pass


class VaultStorage:
    """Manages vault data storage and retrieval"""
    
    def __init__(self, vault_path: str = DEFAULT_VAULT_PATH):
        self.vault_path = Path(vault_path)
        self.config_path = Path(DEFAULT_CONFIG_PATH)
        self.crypto = VaultCrypto()
        self.logger = logging.getLogger(__name__)
        
        # Ensure vault directory exists
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
    
    def vault_exists(self) -> bool:
        """Check if vault file exists"""
        return self.vault_path.exists() and self.vault_path.stat().st_size > 0
    
    def create_vault(self, master_password: str, initial_data: Optional[Dict] = None) -> bool:
        """Create new vault with master password"""
        try:
            if self.vault_exists():
                raise StorageError("Vault already exists")
            
            # Generate salt for key derivation
            salt = self.crypto.generate_salt()
            
            # Derive master key
            master_key = self.crypto.derive_key(master_password, salt)
            
            # Create verification hash
            verification = self.crypto.generate_master_key_verification(master_key)
            
            # Prepare vault metadata
            vault_metadata = {
                "version": "1.0",
                "created": datetime.now().isoformat(),
                "last_modified": datetime.now().isoformat(),
                "salt": salt.hex(),
                "verification": verification,
                "entry_count": 0,
                "last_entry_id": 0
            }
            
            # Prepare initial vault data
            if initial_data is None:
                initial_data = {
                    "entries": {},
                    "tags": {},
                    "history": []
                }
            
            # Encrypt and save vault data
            vault_data = {
                "metadata": vault_metadata,
                "data": initial_data
            }
            
            return self._save_encrypted_vault(vault_data, master_key)
            
        except Exception as e:
            self.logger.error(f"Failed to create vault: {str(e)}")
            raise StorageError(f"Failed to create vault: {str(e)}")
    
    def load_vault(self, master_password: str):
        """Load and decrypt vault data"""
        try:
            if not self.vault_exists():
                raise StorageError("Vault does not exist")
            
            # Read encrypted vault file
            with open(self.vault_path, 'rb') as f:
                encrypted_data = f.read()
            
            if len(encrypted_data) == 0:
                raise StorageError("Vault file is empty")
            
            # Try to decrypt metadata first to get salt
            try:
                # The vault file structure: [metadata_length(4bytes)][encrypted_metadata][encrypted_data]
                metadata_length = int.from_bytes(encrypted_data[:4], 'big')
                encrypted_metadata = encrypted_data[4:4+metadata_length]
                encrypted_vault_data = encrypted_data[4+metadata_length:]
                
                # For first attempt, we need to derive key to decrypt metadata
                # We'll use a default salt extraction method
                temp_salt = encrypted_metadata[:32]  # First 32 bytes as temp salt
                temp_key = self.crypto.derive_key(master_password, temp_salt)
                
                # This is a simplified approach - in production, metadata might be stored separately
                # For now, let's implement a basic structure
                
            except Exception:
                # Fallback: assume the entire file is vault data with embedded salt
                pass
            
            # Try to load using embedded salt method
            vault_data = self._load_encrypted_vault(encrypted_data, master_password)
            
            # Verify master key
            metadata = vault_data.get("metadata", {})
            verification = metadata.get("verification")
            salt = bytes.fromhex(metadata.get("salt", ""))
            master_key = self.crypto.derive_key(master_password, salt)
            
            if not self.crypto.verify_master_key(master_key, verification):
                raise StorageError("Invalid master password")
            
            return vault_data, master_key
            
        except CryptoError:
            raise StorageError("Invalid master password")
        except Exception as e:
            self.logger.error(f"Failed to load vault: {str(e)}")
            raise StorageError(f"Failed to load vault: {str(e)}")
    
    def save_vault(self, vault_data: Dict, master_key: bytes) -> bool:
        """Save vault data with encryption"""
        try:
            # Update last modified timestamp
            if "metadata" in vault_data:
                vault_data["metadata"]["last_modified"] = datetime.now().isoformat()
            
            return self._save_encrypted_vault(vault_data, master_key)
            
        except Exception as e:
            self.logger.error(f"Failed to save vault: {str(e)}")
            raise StorageError(f"Failed to save vault: {str(e)}")
    
    def _save_encrypted_vault(self, vault_data: Dict, master_key: bytes, target_path: Path | None = None) -> bool:
        """Internal method to encrypt and save vault data.

        File format (v1):
            [32-byte salt][AES-GCM(iv + ciphertext + tag)]

        The salt is stored in clear so the key can be re-derived on load.
        """
        try:
            target = target_path or self.vault_path

            # Convert to JSON
            json_data = json.dumps(vault_data, indent=2).encode('utf-8')

            # Encrypt payload
            encrypted_payload = self.crypto.encrypt_data(json_data, master_key)

            # Prepend salt (hex stored in metadata)
            salt_hex = vault_data.get('metadata', {}).get('salt')
            if not salt_hex:
                raise StorageError("Vault metadata missing salt")
            salt_bytes = bytes.fromhex(salt_hex)
            if len(salt_bytes) != 32:
                raise StorageError("Invalid salt length in metadata")

            file_bytes = salt_bytes + encrypted_payload

            # Write atomically
            temp_path = target.with_suffix(target.suffix + '.tmp')
            with open(temp_path, 'wb') as f:
                f.write(file_bytes)
            shutil.move(str(temp_path), str(target))

            self.logger.info(f"Vault saved successfully -> {target}")
            return True

        except Exception as e:
            try:
                if 'temp_path' in locals() and temp_path.exists():
                    temp_path.unlink()
            finally:
                pass
            raise e
    
    def _load_encrypted_vault(self, encrypted_data: bytes, master_password: str) -> Dict:
        """Internal method to decrypt vault data"""
        try:
            # Extract salt from the beginning of encrypted data
            # For simplicity, we'll embed salt in the encrypted data
            salt_length = 32
            if len(encrypted_data) < salt_length:
                raise CryptoError("Invalid vault file format")
            
            # Extract salt and derive key
            embedded_salt = encrypted_data[:salt_length]
            actual_encrypted_data = encrypted_data[salt_length:]
            
            master_key = self.crypto.derive_key(master_password, embedded_salt)
            
            # Decrypt data
            decrypted_data = self.crypto.decrypt_data(actual_encrypted_data, master_key)
            
            # Parse JSON
            vault_data = json.loads(decrypted_data.decode('utf-8'))
            
            return vault_data
            
        except json.JSONDecodeError as e:
            raise CryptoError(f"Invalid vault data format: {str(e)}")
        except Exception as e:
            raise CryptoError(f"Failed to decrypt vault: {str(e)}")
    
    def backup_vault(self, backup_path: Optional[str] = None) -> str:
        """Create backup of vault file"""
        try:
            if not self.vault_exists():
                raise StorageError("No vault to backup")
            
            if backup_path is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = str(self.vault_path.with_suffix(f".{timestamp}{BACKUP_EXTENSION}"))
            
            shutil.copy2(str(self.vault_path), backup_path)
            
            self.logger.info(f"Vault backed up to: {backup_path}")
            return backup_path
            
        except Exception as e:
            self.logger.error(f"Failed to backup vault: {str(e)}")
            raise StorageError(f"Failed to backup vault: {str(e)}")
    
    def restore_vault(self, backup_path: str, master_password: str) -> bool:
        """Restore vault from backup"""
        try:
            if not Path(backup_path).exists():
                raise StorageError("Backup file does not exist")
            
            # Verify backup is valid by trying to load it
            with open(backup_path, 'rb') as f:
                backup_data = f.read()
            
            # Test decrypt the backup
            test_vault_data = self._load_encrypted_vault(backup_data, master_password)
            
            # If successful, copy backup to vault location
            shutil.copy2(backup_path, str(self.vault_path))
            
            self.logger.info(f"Vault restored from: {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to restore vault: {str(e)}")
            raise StorageError(f"Failed to restore vault: {str(e)}")
    
    def export_vault(self, export_path: str, master_password: str, encrypt_export: bool = True) -> bool:
        """Export vault data for backup/transfer"""
        try:
            # Load vault data
            vault_data, master_key = self.load_vault(master_password)
            
            if encrypt_export:
                # Export encrypted to the provided path (do not overwrite main vault)
                return self._save_encrypted_vault(vault_data, master_key, Path(export_path))
            else:
                # Export as plain JSON (warning: unencrypted)
                with open(export_path, 'w', encoding='utf-8') as f:
                    json.dump(vault_data, f, indent=2)
                
                self.logger.warning(f"Vault exported as UNENCRYPTED JSON to: {export_path}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to export vault: {str(e)}")
            raise StorageError(f"Failed to export vault: {str(e)}")
    
    def import_vault(self, import_path: str, master_password: str, encrypted: bool = True) -> bool:
        """Import vault data"""
        try:
            if self.vault_exists():
                raise StorageError("Cannot import: vault already exists")
            
            if not Path(import_path).exists():
                raise StorageError("Import file does not exist")
            
            if encrypted:
                # Import encrypted vault
                with open(import_path, 'rb') as f:
                    import_data = f.read()
                
                # Test decrypt
                vault_data = self._load_encrypted_vault(import_data, master_password)
                
                # Copy to vault location
                shutil.copy2(import_path, str(self.vault_path))
                
            else:
                # Import plain JSON
                with open(import_path, 'r', encoding='utf-8') as f:
                    vault_data = json.load(f)
                
                # Generate new salt and encrypt
                salt = self.crypto.generate_salt()
                master_key = self.crypto.derive_key(master_password, salt)
                
                # Update metadata
                vault_data["metadata"]["salt"] = salt.hex()
                vault_data["metadata"]["verification"] = self.crypto.generate_master_key_verification(master_key)
                
                # Save encrypted
                self._save_encrypted_vault(vault_data, master_key)
            
            self.logger.info(f"Vault imported from: {import_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to import vault: {str(e)}")
            raise StorageError(f"Failed to import vault: {str(e)}")
    
    def get_vault_info(self) -> Dict[str, Any]:
        """Get basic vault information without decrypting"""
        try:
            if not self.vault_exists():
                return {"exists": False}
            
            stat = self.vault_path.stat()
            
            return {
                "exists": True,
                "path": str(self.vault_path),
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get vault info: {str(e)}")
            return {"exists": False, "error": str(e)}
    
    def secure_delete_vault(self) -> bool:
        """Securely delete vault file"""
        try:
            if not self.vault_exists():
                return True
            
            # Simple secure delete - overwrite with random data multiple times
            file_size = self.vault_path.stat().st_size
            
            with open(self.vault_path, 'r+b') as f:
                for _ in range(3):  # Overwrite 3 times
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Finally delete the file
            self.vault_path.unlink()
            
            self.logger.info("Vault securely deleted")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to securely delete vault: {str(e)}")
            raise StorageError(f"Failed to securely delete vault: {str(e)}")


if __name__ == "__main__":
    # Basic test
    import tempfile
    
    # Test in temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        vault_path = os.path.join(temp_dir, "test_vault.dat")
        storage = VaultStorage(vault_path)
        
        # Create test vault
        password = "test_password_123"
        print("Creating test vault...")
        
        initial_data = {
            "entries": {
                "1": {
                    "id": "1",
                    "title": "Test Entry",
                    "type": "note",
                    "content": "This is a test note",
                    "created": datetime.now().isoformat()
                }
            },
            "tags": {"test": ["1"]},
            "history": []
        }
        
        success = storage.create_vault(password, initial_data)
        print(f"Vault created: {success}")
        
        # Load vault
        print("Loading vault...")
        vault_data, master_key = storage.load_vault(password)
        print(f"Loaded {len(vault_data['data']['entries'])} entries")
        
        # Test backup
        print("Creating backup...")
        backup_path = storage.backup_vault()
        print(f"Backup created: {backup_path}")
        
        # Get vault info
        info = storage.get_vault_info()
        print(f"Vault info: {info}")
        
        print("Test completed successfully!")
