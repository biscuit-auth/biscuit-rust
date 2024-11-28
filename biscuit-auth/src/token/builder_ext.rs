use std::time::SystemTime;

pub trait BuilderExt {
    fn add_resource(self, name: &str) -> Self;
    fn check_resource(self, name: &str) -> Self;
    fn check_resource_prefix(self, prefix: &str) -> Self;
    fn check_resource_suffix(self, suffix: &str) -> Self;
    fn add_operation(self, name: &str) -> Self;
    fn check_operation(self, name: &str) -> Self;
    fn check_expiration_date(self, date: SystemTime) -> Self;
}

pub trait AuthorizerExt {
    fn add_allow_all(self) -> Self;
    fn add_deny_all(self) -> Self;
}
