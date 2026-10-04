pub mod certificates;
pub mod consent;
pub mod drivers;
pub mod installed;
pub mod persistence;

pub use certificates::WindowsCertificatesCollector;
pub use consent::WindowsConsentStoreCollector;
pub use drivers::WindowsDriversCollector;
pub use installed::WindowsInstalledSoftwareCollector;
pub use persistence::WindowsPersistenceCollector;
