pub mod certificates;
pub mod consent;
pub mod drivers;
pub mod installed;
pub mod persistence;
pub mod services;
pub mod wmi_persistence;

pub use certificates::WindowsCertificatesCollector;
pub use consent::WindowsConsentStoreCollector;
pub use drivers::WindowsDriversCollector;
pub use installed::WindowsInstalledSoftwareCollector;
pub use persistence::WindowsPersistenceCollector;
pub use services::WindowsServicesCollector;
pub use wmi_persistence::WindowsWmiPersistenceCollector;
