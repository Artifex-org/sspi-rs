//! Server-side Kerberos acceptance of a self-built AP-REQ: a ticket encrypted with the service key
//! and an authenticator encrypted with the ticket session key, as a KDC and a client produce them,
//! accepted without a KDC.

use std::time::Duration;

use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_krb::constants::gss_api::AP_REP_TOKEN_ID;
use picky_krb::constants::key_usages::{AP_REP_ENC, AP_REQ_AUTHENTICATOR, TICKET_REP};
use picky_krb::constants::types::{AP_REQ_MSG_TYPE, NT_ENTERPRISE, NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    ApOptions, Authenticator, AuthenticatorInner, EncApRepPart, EncTicketPart, EncTicketPartInner, EncryptedData,
    EncryptionKey, KerberosFlags, KerberosStringAsn1, KerberosTime, PrincipalName, Ticket, TicketInner,
    TransitedEncoding,
};
use picky_krb::messages::{ApRep, ApReq, ApReqInner};
use time::OffsetDateTime;

use super::{ClientPrincipal, ServerProperties};
use crate::kerberos::messages::{decode_krb_message, generate_krb_message};
use crate::{
    BufferType, CredentialsBuffers, DataRepresentation, Kerberos, KerberosConfig, Secret, SecurityBuffer,
    SecurityStatus, ServerRequestFlags, Sspi, SspiImpl, Username,
};

const SERVICE: [&str; 2] = ["HTTP", "gw.example.com"];
const SERVICE_REALM: &str = "EXAMPLE.COM";
const SERVICE_KEY: [u8; 32] = [0x42; 32];
const SESSION_KEY_AES256: [u8; 32] = [0x17; 32];
const SESSION_KEY_AES128: [u8; 16] = [0x71; 16];
/// `ap-options` bit 2 (RFC 4120 §5.5.1).
const MUTUAL_REQUIRED: u32 = 0x2000_0000;

fn kerberos_string(value: &str) -> KerberosStringAsn1 {
    KerberosStringAsn1::from(IA5String::from_string(value.to_owned()).unwrap())
}

fn principal_name(name_type: u8, components: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
            components
                .iter()
                .map(|component| kerberos_string(component))
                .collect::<Vec<_>>(),
        )),
    }
}

fn kerberos_time(at: OffsetDateTime) -> KerberosTime {
    KerberosTime::from(
        GeneralizedTime::new(
            u16::try_from(at.year()).unwrap(),
            u8::from(at.month()),
            at.day(),
            at.hour(),
            at.minute(),
            at.second(),
        )
        .unwrap(),
    )
}

/// The AES suite and its etype number for a key of this length.
fn aes_suite(key: &[u8]) -> (CipherSuite, u8) {
    match key.len() {
        16 => (CipherSuite::Aes128CtsHmacSha196, 17),
        32 => (CipherSuite::Aes256CtsHmacSha196, 18),
        other => panic!("no AES key of {other} bytes"),
    }
}

/// The AP-REQ of a client named `cname` (of `name_type`) in `crealm`.
struct TestApReq<'a> {
    session_key: &'a [u8],
    name_type: u8,
    cname: &'a [&'a str],
    crealm: &'a str,
    mutual: bool,
}

impl TestApReq<'_> {
    fn client(&self) -> (PrincipalName, KerberosStringAsn1) {
        (principal_name(self.name_type, self.cname), kerberos_string(self.crealm))
    }

    fn ticket(&self, now: OffsetDateTime) -> Ticket {
        let (cname, crealm) = self.client();
        let (_, session_etype) = aes_suite(self.session_key);
        let enc_part = EncTicketPart::from(EncTicketPartInner {
            flags: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(vec![0x40, 0x80, 0x00, 0x00]))),
            key: ExplicitContextTag1::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![session_etype])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(self.session_key.to_vec())),
            }),
            crealm: ExplicitContextTag2::from(crealm),
            cname: ExplicitContextTag3::from(cname),
            transited: ExplicitContextTag4::from(TransitedEncoding {
                tr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
                contents: ExplicitContextTag1::from(OctetStringAsn1::from(Vec::new())),
            }),
            auth_time: ExplicitContextTag5::from(kerberos_time(now - time::Duration::minutes(1))),
            starttime: Optional::from(Some(ExplicitContextTag6::from(kerberos_time(
                now - time::Duration::minutes(1),
            )))),
            endtime: ExplicitContextTag7::from(kerberos_time(now + time::Duration::hours(10))),
            renew_till: Optional::from(None),
            caddr: Optional::from(None),
            authorization_data: Optional::from(None),
        });
        let (service_suite, service_etype) = aes_suite(&SERVICE_KEY);
        let cipher = service_suite
            .cipher()
            .encrypt(&SERVICE_KEY, TICKET_REP, &picky_asn1_der::to_vec(&enc_part).unwrap())
            .unwrap();

        Ticket::from(TicketInner {
            tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            realm: ExplicitContextTag1::from(kerberos_string(SERVICE_REALM)),
            sname: ExplicitContextTag2::from(principal_name(NT_SRV_INST, &SERVICE)),
            enc_part: ExplicitContextTag3::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![service_etype])),
                kvno: Optional::from(Some(ExplicitContextTag1::from(IntegerAsn1::from(vec![3])))),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher)),
            }),
        })
    }

    /// The AP-REQ in its GSS-API framing, as a client sends it.
    fn token(&self) -> Vec<u8> {
        let now = OffsetDateTime::now_utc();
        let (cname, crealm) = self.client();
        let authenticator = Authenticator::from(AuthenticatorInner {
            authenticator_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            crealm: ExplicitContextTag1::from(crealm),
            cname: ExplicitContextTag2::from(cname),
            cksum: Optional::from(None),
            cusec: ExplicitContextTag4::from(IntegerAsn1::from(vec![1])),
            ctime: ExplicitContextTag5::from(kerberos_time(now)),
            subkey: Optional::from(None),
            seq_number: Optional::from(None),
            authorization_data: Optional::from(None),
        });
        let (session_suite, session_etype) = aes_suite(self.session_key);
        let cipher = session_suite
            .cipher()
            .encrypt(
                self.session_key,
                AP_REQ_AUTHENTICATOR,
                &picky_asn1_der::to_vec(&authenticator).unwrap(),
            )
            .unwrap();
        let ap_options = if self.mutual { MUTUAL_REQUIRED } else { 0 };
        let ap_req = ApReq::from(ApReqInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
            ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(
                ap_options.to_be_bytes().to_vec(),
            ))),
            ticket: ExplicitContextTag3::from(self.ticket(now)),
            authenticator: ExplicitContextTag4::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![session_etype])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher)),
            }),
        });

        generate_krb_message(
            picky::oids::krb5(),
            picky_krb::constants::gss_api::AP_REQ_TOKEN_ID,
            ap_req,
        )
        .unwrap()
    }
}

/// A server context for [`SERVICE`] with [`SERVICE_KEY`] and no KDC.
fn server() -> Kerberos {
    let properties = ServerProperties::new(
        &SERVICE,
        None,
        Duration::from_secs(5 * 60),
        Some(Secret::new(SERVICE_KEY.to_vec())),
    )
    .unwrap();

    Kerberos::new_server_from_config(
        KerberosConfig {
            kdc_url: None,
            client_computer_name: String::new(),
        },
        properties,
    )
    .unwrap()
}

/// Accepts `token` on `server`; returns the status and the output token.
fn accept(server: &mut Kerberos, token: Vec<u8>) -> (SecurityStatus, Vec<u8>) {
    let mut credentials: Option<CredentialsBuffers> = None;
    let mut input = [SecurityBuffer::new(token, BufferType::Token)];
    let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let builder = server
        .accept_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ServerRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_input(&mut input)
        .with_output(&mut output);
    // The trait method (the inherent one of the same name is the async state machine).
    let status = SspiImpl::accept_security_context_impl(server, builder)
        .unwrap()
        .resolve_to_result()
        .unwrap()
        .status;
    let [output] = output;

    (status, output.buffer)
}

#[test]
fn client_principal_is_reported_verbatim() {
    let mut kerberos = server();
    assert_eq!(kerberos.client_principal(), None);

    let ap_req = TestApReq {
        session_key: &SESSION_KEY_AES256,
        name_type: NT_PRINCIPAL,
        cname: &["Alice", "admin"],
        crealm: "Corp.Example.COM",
        mutual: false,
    };
    let (status, _) = accept(&mut kerberos, ap_req.token());

    assert_eq!(status, SecurityStatus::Ok);
    // Every component, the name type and the realm, without case folding.
    assert_eq!(
        kerberos.client_principal(),
        Some(&ClientPrincipal {
            name_type: i32::from(NT_PRINCIPAL),
            name_components: vec!["Alice".to_owned(), "admin".to_owned()],
            realm: "Corp.Example.COM".to_owned(),
        })
    );
    // The lossy view is unchanged: first component, lower-cased realm.
    assert_eq!(
        kerberos.query_context_names().unwrap().username,
        Username::new_upn("Alice", "corp.example.com").unwrap()
    );
}

#[test]
fn enterprise_client_principal_keeps_its_realm() {
    let mut kerberos = server();
    let ap_req = TestApReq {
        session_key: &SESSION_KEY_AES256,
        name_type: NT_ENTERPRISE,
        cname: &["alice@corp.example.com"],
        crealm: "EXAMPLE.COM",
        mutual: false,
    };
    let (status, _) = accept(&mut kerberos, ap_req.token());

    assert_eq!(status, SecurityStatus::Ok);
    assert_eq!(
        kerberos.client_principal(),
        Some(&ClientPrincipal {
            name_type: i32::from(NT_ENTERPRISE),
            name_components: vec!["alice@corp.example.com".to_owned()],
            realm: "EXAMPLE.COM".to_owned(),
        })
    );
}

#[test]
fn client_principal_is_not_set_for_a_rejected_ticket() {
    let mut kerberos = server();
    let mut token = TestApReq {
        session_key: &SESSION_KEY_AES256,
        name_type: NT_PRINCIPAL,
        cname: &["alice"],
        crealm: SERVICE_REALM,
        mutual: false,
    }
    .token();
    // Corrupt the authenticator ciphertext (the last bytes of the token).
    let last = token.len() - 1;
    token[last] ^= 0x01;

    let mut credentials: Option<CredentialsBuffers> = None;
    let mut input = [SecurityBuffer::new(token, BufferType::Token)];
    let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let builder = kerberos
        .accept_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ServerRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_input(&mut input)
        .with_output(&mut output);
    let result = SspiImpl::accept_security_context_impl(&mut kerberos, builder)
        .and_then(|mut generator| generator.resolve_to_result());

    assert!(result.is_err());
    assert_eq!(kerberos.client_principal(), None);
}

#[test]
fn ap_rep_is_encrypted_with_the_session_key_type() {
    for session_key in [&SESSION_KEY_AES128[..], &SESSION_KEY_AES256[..]] {
        let (suite, etype) = aes_suite(session_key);
        let mut kerberos = server();
        let ap_req = TestApReq {
            session_key,
            name_type: NT_PRINCIPAL,
            cname: &["alice"],
            crealm: SERVICE_REALM,
            mutual: true,
        };
        let (status, output) = accept(&mut kerberos, ap_req.token());
        assert_eq!(status, SecurityStatus::Ok);

        let ap_rep: ApRep = decode_krb_message(&output, AP_REP_TOKEN_ID).unwrap();
        let enc_part = &ap_rep.0.enc_part.0;
        assert_eq!(
            enc_part.etype.0.0,
            vec![etype],
            "AP-REP etype for a {etype} session key"
        );
        // The client decrypts it with the session key of the ticket.
        let plaintext = suite
            .cipher()
            .decrypt(session_key, AP_REP_ENC, &enc_part.cipher.0.0)
            .unwrap();
        let enc_ap_rep_part: EncApRepPart = picky_asn1_der::from_bytes(&plaintext).unwrap();
        let subkey = &enc_ap_rep_part.0.subkey.0.as_ref().unwrap().0;
        assert_eq!(subkey.key_type.0.0, vec![etype]);
        assert_eq!(subkey.key_value.0.0.len(), session_key.len());
    }
}
