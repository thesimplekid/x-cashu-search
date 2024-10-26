use std::path::PathBuf;

use anyhow::Result;
use cdk::nuts::{Proof, Proofs, PublicKey};
use redb::{Database, ReadableTable, TableDefinition};

// <Y, Proof Info>
const PROOFS_TABLE: TableDefinition<&[u8], &str> = TableDefinition::new("proofs");
// <Y, bool> claimed or not
const CLAIMED_TABLE: TableDefinition<&[u8], bool> = TableDefinition::new("states");

pub struct Db {
    db: Database,
}

impl Db {
    pub fn new(path: PathBuf) -> Result<Self> {
        let db = Database::create(path)?;

        let write_txn = db.begin_write()?;
        {
            // Open all tables to init a new db
            let _ = write_txn.open_table(PROOFS_TABLE)?;
            let _ = write_txn.open_table(CLAIMED_TABLE)?;
        }

        write_txn.commit()?;

        Ok(Self { db })
    }

    pub fn add_unclaimed_proof(&self, proof: &Proof) -> Result<Option<Proof>> {
        let mut old = None;
        let write_txn = self.db.begin_write()?;

        {
            let y = proof.y()?;
            let y_bytes = y.to_bytes();

            let mut proof_table = write_txn.open_table(PROOFS_TABLE)?;

            if let Some(previous) =
                proof_table.insert(y_bytes.as_slice(), serde_json::to_string(proof)?.as_str())?
            {
                old = serde_json::from_str(previous.value())?;
            }

            let mut claimed_table = write_txn.open_table(CLAIMED_TABLE)?;

            claimed_table.insert(y_bytes.as_slice(), false)?;
        }

        write_txn.commit()?;

        Ok(old)
    }

    pub fn remove_proof(&self, proof: &Proof) -> Result<()> {
        let write_txn = self.db.begin_write()?;

        {
            let y = proof.y()?;
            let y_bytes = y.to_bytes();

            let mut proof_table = write_txn.open_table(PROOFS_TABLE)?;

            proof_table.remove(y_bytes.as_slice())?;

            let mut claimed_table = write_txn.open_table(CLAIMED_TABLE)?;
            claimed_table.remove(y_bytes.as_slice())?;
        }

        write_txn.commit()?;

        Ok(())
    }

    pub fn _set_proof_claimed(&self, y: PublicKey) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut claimed_table = write_txn.open_table(CLAIMED_TABLE)?;

            let y_bytes = y.to_bytes();
            claimed_table.insert(y_bytes.as_slice(), true)?;
        }
        write_txn.commit()?;

        Ok(())
    }

    pub fn _get_unclaimed_proofs(&self) -> Result<Proofs> {
        let read_txn = self.db.begin_read()?;
        let state_table = read_txn.open_table(CLAIMED_TABLE)?;

        let unclaimed_ys: Vec<Vec<u8>> = state_table
            .iter()?
            .flatten()
            .filter_map(|(k, v)| {
                if !v.value() {
                    let y = k.value();
                    Some(y.to_vec())
                } else {
                    None
                }
            })
            .collect();

        let mut proofs = Vec::with_capacity(unclaimed_ys.len());

        let proof_table = read_txn.open_table(PROOFS_TABLE)?;

        for y in unclaimed_ys {
            let proof = proof_table.get(y.as_slice())?;

            if let Some(proof) = proof {
                let proof: Proof = serde_json::from_str(proof.value())?;
                proofs.push(proof);
            }
        }

        Ok(proofs)
    }

    pub fn _get_all_ys(&self) -> Result<Vec<PublicKey>> {
        let read_txn = self.db.begin_read()?;
        let proof_table = read_txn.open_table(PROOFS_TABLE)?;

        let ys: Vec<PublicKey> = proof_table
            .iter()?
            .flatten()
            .flat_map(|(k, _v)| PublicKey::from_slice(k.value()))
            .collect();

        Ok(ys)
    }
}
