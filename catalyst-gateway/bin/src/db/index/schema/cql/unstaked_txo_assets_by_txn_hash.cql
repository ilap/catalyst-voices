-- Transaction Outputs (Native Assets) per stake address.
CREATE TABLE IF NOT EXISTS unstaked_txo_assets_by_txn_hash (
    -- Primary Key Fields
    txn_hash        blob,     -- 32 byte hash of this transaction.
    txo             smallint, -- offset in the txo list of the transaction the txo is in.
    policy_id       blob,     -- asset policy hash (id) (28 byte binary hash)
    policy_name     text,     -- name of the policy (UTF8)

    -- Secondary Location information for the transaction.
    slot_no         varint,     -- slot number the txo was created in.
    txn             smallint,   -- Which Transaction in the Slot is the TXO.

    -- Value of the asset.
    value           varint,   -- Value of the asset (u64)

    PRIMARY KEY (txn_hash, txo, policy_id, policy_name)
);
