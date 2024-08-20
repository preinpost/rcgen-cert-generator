use rcgen::{generate_simple_self_signed, CertifiedKey, DnType, DnValue, IsCa, KeyPair};
use rcgen::{CertificateParams, DistinguishedName};
fn main() {
    make_root_cert_client_cert_and_private_key();
}


fn make_root_cert_client_cert_and_private_key() {
    // CA 인증서 생성
    let mut params = CertificateParams::new(vec![]).unwrap();
    let mut dn = DistinguishedName::new();

    dn.push(DnType::OrganizationName, "OrganizationName");
    dn.push(DnType::CommonName, DnValue::PrintableString("Master Cert".try_into().unwrap()));

    params.distinguished_name = dn;
    // params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.is_ca = IsCa::NoCa;
    params.subject_alt_names.push(rcgen::SanType::DnsName("localhost".try_into().unwrap()));

    let ca_key_pair = KeyPair::generate().unwrap();

    let ca_cert =  params.self_signed(&ca_key_pair).unwrap();
    let ca_cert_pem = ca_cert.pem();
    
    std::fs::write("server.crt", ca_cert_pem).unwrap();
    std::fs::write("server.der",  ca_cert.der()).unwrap();
    std::fs::write("server.key", ca_key_pair.serialize_pem()).unwrap();

    // 클라이언트 인증서 생성
    let mut client_params = CertificateParams::new(vec![]).unwrap();
    let mut client_dn = DistinguishedName::new();

    client_dn.push(DnType::CommonName, "My Client");
    
    client_params.distinguished_name = client_dn;
    client_params.subject_alt_names.push(rcgen::SanType::DnsName("localhost".try_into().unwrap()));

    let client_key_pair = KeyPair::generate().unwrap();

    let client_cert = client_params.signed_by(&client_key_pair, &ca_cert, &ca_key_pair).unwrap();
    let client_cert_pem = client_cert.pem();
    
    // 클라이언트 키 생성
    let client_key_pem = client_key_pair.serialize_pem();
    
    std::fs::write("client.crt", client_cert_pem).unwrap();
    std::fs::write("client.key", client_key_pem).unwrap();
}


fn generate_self_signed_key() {
    let subject_alt_names = vec!["hello.world.example".to_string(), "localhost".to_string()];

    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();
    println!("{}", cert.pem());
    println!("{}", key_pair.serialize_pem());
}