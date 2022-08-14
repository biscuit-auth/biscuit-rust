use std::time::SystemTime;

pub trait BuilderExt {
    fn add_resource(&mut self, name: &str);
    fn check_resource(&mut self, name: &str);
    fn check_resource_prefix(&mut self, prefix: &str);
    fn check_resource_suffix(&mut self, suffix: &str);
    fn add_operation(&mut self, name: &str);
    fn check_operation(&mut self, name: &str);
    fn check_expiration_date(&mut self, date: SystemTime);
}

pub trait AuthorizerExt {
    fn add_allow_all(&mut self);
    fn add_deny_all(&mut self);
}
