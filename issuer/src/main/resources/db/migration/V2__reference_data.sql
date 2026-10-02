-- Internal ledger accounts for USD (ISO 4217 numeric 840).
INSERT INTO ledger_accounts (code, kind, normal_side, currency) VALUES
    ('ISSUER_CASH-840',        'ISSUER_CASH',        'D', '840'),
    ('NETWORK_SETTLEMENT-840', 'NETWORK_SETTLEMENT', 'C', '840'),
    ('DISPUTE_RECEIVABLE-840', 'DISPUTE_RECEIVABLE', 'D', '840'),
    ('CHARGEBACK_LOSS-840',    'CHARGEBACK_LOSS',    'D', '840'),
    ('CLEARING_SUSPENSE-840',  'CLEARING_SUSPENSE',  'D', '840');

-- Reason codes modelled on public network dispute rules. Time limits are
-- simplified illustrations, not the networks' current rulebooks.
INSERT INTO dispute_reason_codes
    (code, network, description, chargeback_days, representment_days, prearb_days, required_evidence) VALUES
    ('10.4',   'VISA',       'Other fraud - card-absent environment',         120, 30, 30, 'CARDHOLDER_FRAUD_DECLARATION'),
    ('12.6.1', 'VISA',       'Duplicate processing',                          120, 30, 30, 'TRANSACTION_RECORDS'),
    ('13.1',   'VISA',       'Merchandise/services not received',             120, 30, 30, 'CARDHOLDER_LETTER'),
    ('13.3',   'VISA',       'Not as described or defective merchandise',     120, 30, 30, 'CARDHOLDER_LETTER'),
    ('4837',   'MASTERCARD', 'No cardholder authorization',                   120, 45, 45, 'CARDHOLDER_FRAUD_DECLARATION'),
    ('4834',   'MASTERCARD', 'Point-of-interaction error (duplicate/paid by other means)', 90, 45, 45, 'TRANSACTION_RECORDS'),
    ('4853',   'MASTERCARD', 'Cardholder dispute',                            120, 45, 45, 'CARDHOLDER_LETTER');
