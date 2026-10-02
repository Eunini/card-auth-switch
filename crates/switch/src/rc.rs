//! ISO 8583:1987 response codes used by the switch (field 39).

pub const APPROVED: &str = "00";
pub const DO_NOT_HONOR: &str = "05";
pub const INVALID_TRANSACTION: &str = "12";
pub const INVALID_AMOUNT: &str = "13";
pub const INVALID_CARD: &str = "14";
pub const UNABLE_TO_LOCATE_ORIGINAL: &str = "25";
pub const FORMAT_ERROR: &str = "30";
pub const LOST_CARD: &str = "41";
pub const STOLEN_CARD: &str = "43";
pub const INSUFFICIENT_FUNDS: &str = "51";
pub const EXPIRED_CARD: &str = "54";
pub const INCORRECT_PIN: &str = "55";
pub const NOT_PERMITTED_TO_TERMINAL: &str = "58";
pub const EXCEEDS_AMOUNT_LIMIT: &str = "61";
pub const RESTRICTED_CARD: &str = "62";
pub const EXCEEDS_FREQUENCY_LIMIT: &str = "65";
pub const PIN_TRIES_EXCEEDED: &str = "75";
/// Visa: negative online CAM (ARQC), dCVV, iCVV or CVV result.
pub const CRYPTOGRAPHIC_FAILURE: &str = "82";
pub const ISSUER_UNAVAILABLE: &str = "91";
pub const DUPLICATE_TRANSMISSION: &str = "94";
pub const SYSTEM_MALFUNCTION: &str = "96";

pub fn describe(rc: &str) -> &'static str {
    match rc {
        "00" => "approved",
        "05" => "do not honor",
        "12" => "invalid transaction",
        "13" => "invalid amount",
        "14" => "invalid card number",
        "25" => "unable to locate original",
        "30" => "format error",
        "41" => "lost card",
        "43" => "stolen card",
        "51" => "insufficient funds",
        "54" => "expired card",
        "55" => "incorrect PIN",
        "58" => "not permitted to terminal",
        "61" => "exceeds amount limit",
        "62" => "restricted card",
        "65" => "exceeds frequency limit",
        "75" => "PIN tries exceeded",
        "82" => "cryptogram/CVV check failed",
        "91" => "issuer unavailable",
        "94" => "duplicate transmission",
        "96" => "system malfunction",
        _ => "unknown",
    }
}
