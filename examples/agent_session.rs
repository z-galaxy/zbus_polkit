use nix::unistd::getuid;
use zbus_polkit::polkitagent::PolkitAgentSession;
fn main() {
    let uid = getuid();
    // FOR EXAMPLE, uid is 1000
    let session = PolkitAgentSession::new(uid, None).unwrap();
    println!("{}", session.user_name());
}
