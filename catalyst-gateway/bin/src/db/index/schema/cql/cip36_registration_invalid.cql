-- Index of CIP-36 registrations that are invalid.
CREATE TABLE IF NOT EXISTS cip36_registration_invalid (
    -- Primary Key Data
    stake_address       blob,       -- 32 Bytes of Stake Address.
    slot_no             varint,     -- slot number when the key_was_registered/re-registered.
    txn                 smallint,   -- Index of the TX which holds the registration data.

    -- Non-Key Data
    vote_key            blob,       -- 32 Bytes of Vote Key.
    payment_address     blob,       -- Bytes of address for payment of rewards.
    is_payable          boolean,    -- True if payment to the address is possible.
    raw_nonce           varint,     -- Nonce that has not been slot corrected.
    nonce               varint,     -- Nonce that has been slot corrected.
    cip36               boolean,    -- True if CIP-36 Registration format used. CIP-15 = False.
    signed              boolean,    -- Signature validates.
    error_report        list<text>, -- List of serialization errors in the registration.

    PRIMARY KEY (stake_address, slot_no, txn)
)
WITH CLUSTERING ORDER BY (slot_no DESC, txn DESC);
