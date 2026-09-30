mod bindings {
    #![allow(unknown_lints)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(non_upper_case_globals)]
    #![allow(unsafe_op_in_unsafe_fn)]
    #![allow(unnecessary_transmutes)]
    #![allow(clippy::all)]

    include!("bindings.rs");
}

pub use bindings::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_struct_size_matches_library() {
        let size = unsafe { ndpi_detection_get_sizeof_ndpi_flow_struct() };
        assert_eq!(std::mem::size_of::<ndpi_flow_struct>(), size as usize);
    }

    #[test]
    fn revision_is_6_0() {
        let revision = unsafe { std::ffi::CStr::from_ptr(ndpi_revision()) };
        assert!(revision.to_bytes().starts_with(b"6.0"));
    }
}
