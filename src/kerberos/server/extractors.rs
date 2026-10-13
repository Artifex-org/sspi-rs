use picky_krb::constants::key_usages::{AP_REQ_AUTHENTICATOR, TICKET_REP};
use picky_krb::constants::types::{NT_ENTERPRISE, NT_PRINCIPAL};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{Authenticator, EncTicketPart, KerberosStringAsn1, PrincipalName};
use picky_krb::messages::ApReq;

use picky_asn1::wrapper::IntegerAsn1;

use super::ClientPrincipal;
use crate::{Error, ErrorKind, Result, Secret, Username};

/// Decrypts the [ApReq] ticket and returns decoded encrypted part of the ticket.
pub(super) fn decrypt_ap_req_ticket(key: &Secret<Vec<u8>>, ap_req: &ApReq) -> Result<EncTicketPart> {
    let ticket_enc_part = &ap_req.0.ticket.0.0.enc_part.0;
    let cipher = CipherSuite::try_from(ticket_enc_part.etype.0.0.as_slice())?.cipher();

    let encoded_enc_part = cipher.decrypt(key.as_ref(), TICKET_REP, &ticket_enc_part.cipher.0.0)?;

    Ok(picky_asn1_der::from_bytes(&encoded_enc_part)?)
}

/// Decrypts [ApReq] Authenticator and returns decoded authenticator.
pub(super) fn decrypt_ap_req_authenticator(session_key: &Secret<Vec<u8>>, ap_req: &ApReq) -> Result<Authenticator> {
    let encrypted_authenticator = &ap_req.0.authenticator.0;
    let cipher = CipherSuite::try_from(encrypted_authenticator.etype.0.0.as_slice())?.cipher();

    let encoded_authenticator = cipher.decrypt(
        session_key.as_ref(),
        AP_REQ_AUTHENTICATOR,
        &encrypted_authenticator.cipher.0.0,
    )?;

    Ok(picky_asn1_der::from_bytes(&encoded_authenticator)?)
}

/// Constructs [Username] from the client's [PrincipalName] and realm.
pub(super) fn client_upn(cname: &PrincipalName, crealm: &KerberosStringAsn1) -> Result<Username> {
    let username = cname
        .name_string
        .0
        .0
        .first()
        .map(|name| name.to_string())
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing cname value in token"))?;

    let name_type = &cname.name_type.0.0;
    if name_type == &[NT_PRINCIPAL] {
        Ok(Username::new_upn(
            &username,
            &crealm.0.to_string().to_ascii_lowercase(),
        )?)
    } else if name_type == &[NT_ENTERPRISE] {
        Ok(Username::parse(&username)?)
    } else {
        Err(Error::new(
            ErrorKind::InvalidToken,
            format!("unsupported principal name type: {name_type:?}"),
        ))
    }
}

/// Decodes a Kerberos `Int32` (RFC 4120 §5.2.4).
fn int32(value: &IntegerAsn1) -> Result<i32> {
    let bytes = value.as_signed_bytes_be();
    if bytes.len() > 4 {
        return Err(Error::new(ErrorKind::InvalidToken, "Int32 value is out of range"));
    }
    let fill = if bytes[0] & 0x80 == 0 { 0x00 } else { 0xff };
    let mut be = [fill; 4];
    be[4 - bytes.len()..].copy_from_slice(bytes);

    Ok(i32::from_be_bytes(be))
}

/// Constructs [ClientPrincipal] from the client's [PrincipalName] and realm, without loss.
pub(super) fn client_principal(cname: &PrincipalName, crealm: &KerberosStringAsn1) -> Result<ClientPrincipal> {
    Ok(ClientPrincipal {
        name_type: int32(&cname.name_type.0)?,
        name_components: cname
            .name_string
            .0
            .0
            .iter()
            .map(|component| component.to_string())
            .collect(),
        realm: crealm.0.to_string(),
    })
}
