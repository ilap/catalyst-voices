//! Index RBAC Chain Root For Stake Address Insert Query.
use std::{fmt::Debug, sync::Arc};

use scylla::{SerializeRow, Session};
use tracing::error;

use crate::{
    db::index::queries::{PreparedQueries, SizedBatch},
    settings::cassandra_db::EnvVars,
};

/// Index RBAC Chain Root by Stake Address
const INSERT_CHAIN_ROOT_FOR_STAKE_ADDRESS_QUERY: &str =
    include_str!("./cql/insert_chain_root_for_stake_address.cql");

/// Insert Chain Root For Stake Address Query Parameters
#[derive(SerializeRow)]
pub(crate) struct Params {
    /// Stake Address Hash. 32 bytes.
    stake_addr: Vec<u8>,
    /// Block Slot Number
    slot_no: num_bigint::BigInt,
    /// Transaction Offset inside the block.
    txn: i16,
    /// Chain Root Hash. 32 bytes.
    chain_root: Vec<u8>,
}

impl Debug for Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Params")
            .field("stake_addr", &self.stake_addr)
            .field("slot_no", &self.slot_no)
            .field("txn", &self.txn)
            .field("chain_root", &self.chain_root)
            .finish()
    }
}

impl Params {
    /// Create a new record for this transaction.
    pub(crate) fn new(stake_addr: &[u8], chain_root: &[u8], slot_no: u64, txn: i16) -> Self {
        Params {
            stake_addr: stake_addr.to_vec(),
            slot_no: num_bigint::BigInt::from(slot_no),
            txn,
            chain_root: chain_root.to_vec(),
        }
    }

    /// Prepare Batch of RBAC Registration Index Data Queries
    pub(crate) async fn prepare_batch(
        session: &Arc<Session>, cfg: &EnvVars,
    ) -> anyhow::Result<SizedBatch> {
        PreparedQueries::prepare_batch(
            session.clone(),
            INSERT_CHAIN_ROOT_FOR_STAKE_ADDRESS_QUERY,
            cfg,
            scylla::statement::Consistency::Any,
            true,
            false,
        )
        .await
        .inspect_err(|error| error!(error=%error,"Failed to prepare Insert Chain Root For Stake Address Query."))
        .map_err(|error| anyhow::anyhow!("{error}\n--\n{INSERT_CHAIN_ROOT_FOR_STAKE_ADDRESS_QUERY}"))
    }
}
