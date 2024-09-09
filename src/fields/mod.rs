mod extensions;

pub(crate) mod fp;

// TODO(It feels like this could be significantly DRY'd using the principle appiled in the `groups` module)
// Perhaps reducing the cost and complexity of the audit, unfortunately not for the base field, but for
// the extensions.

pub(crate) mod fp12;
pub(crate) mod fp2;
pub(crate) mod fp6;
