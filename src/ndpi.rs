// SPDX-FileCopyrightText: 2026 Open Information Security Foundation
// SPDX-License-Identifier: LGPL-3.0-only

use std::ffi::{CStr, CString};
use std::mem;
use std::os::raw::c_char;
use std::ptr::{self, NonNull};

use ndpi_sys as ffi;

use suricatax80_plugin_utils as suricata;

pub struct DetectionModule {
    ptr: NonNull<ffi::ndpi_detection_module_struct>,
}

impl DetectionModule {
    pub fn new() -> Option<Self> {
        unsafe {
            let ptr = ffi::ndpi_init_detection_module(ptr::null_mut());
            let ptr = NonNull::new(ptr)?;
            if ffi::ndpi_finalize_initialization(ptr.as_ptr()) != 0 {
                ffi::ndpi_exit_detection_module(ptr.as_ptr());
                return None;
            }
            Some(Self { ptr })
        }
    }

    pub fn revision() -> Option<&'static CStr> {
        unsafe {
            let revision = ffi::ndpi_revision();
            if revision.is_null() {
                None
            } else {
                Some(CStr::from_ptr(revision))
            }
        }
    }

    pub unsafe fn protocol_by_name(
        &mut self,
        name: *const c_char,
    ) -> ffi::ndpi_master_app_protocol {
        ffi::ndpi_get_protocol_by_name(self.ptr.as_ptr(), name)
    }

    pub fn as_ptr(&self) -> *mut ffi::ndpi_detection_module_struct {
        self.ptr.as_ptr()
    }
}

impl Drop for DetectionModule {
    fn drop(&mut self) {
        unsafe {
            ffi::ndpi_exit_detection_module(self.ptr.as_ptr());
        }
    }
}

pub struct Flow {
    ptr: NonNull<ffi::ndpi_flow_struct>,
    detected_l7_protocol: ffi::ndpi_protocol,
    detection_completed: bool,
}

impl Flow {
    pub fn new() -> Option<Self> {
        unsafe {
            let ptr = ffi::ndpi_flow_malloc(mem::size_of::<ffi::ndpi_flow_struct>())
                .cast::<ffi::ndpi_flow_struct>();
            let ptr = NonNull::new(ptr)?;
            ptr::write_bytes(
                ptr.as_ptr().cast::<u8>(),
                0,
                mem::size_of::<ffi::ndpi_flow_struct>(),
            );
            Some(Self {
                ptr,
                detected_l7_protocol: mem::zeroed(),
                detection_completed: false,
            })
        }
    }

    pub fn detection_completed(&self) -> bool {
        self.detection_completed
    }

    pub fn process_packet(
        &mut self,
        module: &mut DetectionModule,
        packet: *const u8,
        packet_len: u16,
        time_ms: u64,
        l4_proto: u8,
        packet_count: u32,
    ) {
        if self.detection_completed || packet.is_null() || packet_len == 0 {
            return;
        }

        unsafe {
            self.detected_l7_protocol = ffi::ndpi_detection_process_packet(
                module.as_ptr(),
                self.ptr.as_ptr(),
                packet,
                packet_len,
                time_ms,
                ptr::null_mut(),
            );

            if ffi::ndpi_is_protocol_detected(self.detected_l7_protocol) != 0 {
                if !ffi::ndpi_is_proto_unknown(self.detected_l7_protocol.proto) {
                    let flow = self.ptr.as_ref();
                    let extra_done =
                        flow.num_extra_packets_checked >= flow.max_extra_packets_to_check;
                    if self.detected_l7_protocol.state
                        == ffi::ndpi_classification_state_NDPI_STATE_CLASSIFIED
                        || extra_done
                    {
                        self.detection_completed = true;
                    }
                }
            } else {
                let max_num_pkts = if l4_proto == suricata::IPPROTO_UDP {
                    8
                } else {
                    24
                };
                if packet_count > max_num_pkts {
                    self.detected_l7_protocol =
                        ffi::ndpi_detection_giveup(module.as_ptr(), self.ptr.as_ptr());
                    self.detection_completed = true;
                }
            }
        }
    }

    pub fn protocol_matches(&self, proto: ffi::ndpi_master_app_protocol, negated: bool) -> bool {
        unsafe {
            ffi::ndpi_is_proto_equals(self.detected_l7_protocol.proto, proto, false) ^ negated
        }
    }

    pub fn risk_matches(&self, risk_mask: ffi::ndpi_risk, negated: bool) -> bool {
        let matched = unsafe { (self.ptr.as_ref().risk & risk_mask) == risk_mask };
        matched ^ negated
    }

    pub unsafe fn write_json(
        &mut self,
        module: &mut DetectionModule,
        jb: *mut suricata::SCJsonBuilder,
    ) {
        if jb.is_null() {
            return;
        }

        let mut serializer: ffi::ndpi_serializer = mem::zeroed();
        if ffi::ndpi_init_serializer(
            &mut serializer,
            ffi::ndpi_serialization_format_ndpi_serialization_format_inner_json,
        ) != 0
        {
            return;
        }

        ffi::ndpi_dpi2json(
            module.as_ptr(),
            self.ptr.as_ptr(),
            self.detected_l7_protocol,
            &mut serializer,
        );

        let mut buffer_len = 0;
        let buffer = ffi::ndpi_serializer_get_buffer(&mut serializer, &mut buffer_len);
        if !buffer.is_null() && buffer_len > 0 {
            let buffer = std::slice::from_raw_parts(buffer.cast::<u8>(), buffer_len as usize);
            if let Some(formatted) = validate_inner_json(buffer) {
                suricata::scjb_set_formatted(jb, formatted.as_ptr());
            }
        }

        ffi::ndpi_term_serializer(&mut serializer);
    }
}

fn validate_inner_json(fragment: &[u8]) -> Option<CString> {
    let mut wrapped = Vec::with_capacity(fragment.len() + 2);
    wrapped.push(b'{');
    wrapped.extend_from_slice(fragment);
    wrapped.push(b'}');

    let mut value: serde_json::Value = serde_json::from_slice(&wrapped).ok()?;
    if !value.is_object() {
        return None;
    }
    sanitize_json_keys(&mut value);

    let rendered = serde_json::to_string(&value).ok()?;
    let inner = rendered.strip_prefix('{')?.strip_suffix('}')?;
    if inner.is_empty() {
        return None;
    }

    CString::new(inner).ok()
}

fn sanitize_json_keys(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let old_map = mem::take(map);
            for (key, mut value) in old_map {
                sanitize_json_keys(&mut value);
                map.insert(key.replace('.', "_"), value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                sanitize_json_keys(value);
            }
        }
        _ => {}
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        unsafe {
            ffi::ndpi_flow_free(self.ptr.as_ptr().cast());
        }
    }
}

pub fn parse_protocol(name: *const c_char) -> Option<ffi::ndpi_master_app_protocol> {
    if name.is_null() {
        return None;
    }

    let mut module = DetectionModule::new()?;
    let proto = unsafe { module.protocol_by_name(name) };
    let unknown = unsafe { ffi::ndpi_is_proto_unknown(proto) };
    if unknown {
        None
    } else {
        Some(proto)
    }
}

pub unsafe fn parse_risk(arg: *const c_char) -> Option<ffi::ndpi_risk> {
    if arg.is_null() {
        return None;
    }

    let arg = CStr::from_ptr(arg);
    let bytes = arg.to_bytes();
    if bytes.is_empty() {
        return None;
    }

    if bytes[0].is_ascii_digit() {
        return std::str::from_utf8(bytes)
            .ok()?
            .parse::<ffi::ndpi_risk>()
            .ok();
    }

    let mut risk_mask: ffi::ndpi_risk = 0;
    for token in bytes.split(|b| *b == b',') {
        if token.is_empty() {
            continue;
        }
        let token = CString::new(token).ok()?;
        let risk_id = ffi::ndpi_code2risk(token.as_ptr());
        if risk_id >= ffi::ndpi_risk_enum_NDPI_MAX_RISK {
            return None;
        }
        risk_mask |= 1u64 << risk_id;
    }

    Some(risk_mask)
}

pub fn protocols_equal(
    to_check: ffi::ndpi_master_app_protocol,
    to_match: ffi::ndpi_master_app_protocol,
    exact_match_only: bool,
) -> bool {
    unsafe { ffi::ndpi_is_proto_equals(to_check, to_match, exact_match_only) }
}

pub type Protocol = ffi::ndpi_master_app_protocol;
pub type Risk = ffi::ndpi_risk;

#[cfg(test)]
mod tests {
    use super::validate_inner_json;

    #[test]
    fn validate_inner_json_reserializes_valid_fragment() {
        let formatted =
            validate_inner_json(br#""ndpi":{"proto":"HTTP","hostname":"example.com"}"#).unwrap();

        let mut wrapped = Vec::new();
        wrapped.push(b'{');
        wrapped.extend_from_slice(formatted.to_bytes());
        wrapped.push(b'}');

        let value: serde_json::Value = serde_json::from_slice(&wrapped).unwrap();
        assert_eq!(value["ndpi"]["proto"], "HTTP");
        assert_eq!(value["ndpi"]["hostname"], "example.com");
    }

    #[test]
    fn validate_inner_json_replaces_dots_in_field_names() {
        let formatted = validate_inner_json(
            br#""ndpi":{"ONE.TWO.THREE":"value","nested.object":{"array.value":[{"leaf.name":1}]}}"#,
        )
        .unwrap();

        let mut wrapped = Vec::new();
        wrapped.push(b'{');
        wrapped.extend_from_slice(formatted.to_bytes());
        wrapped.push(b'}');

        let value: serde_json::Value = serde_json::from_slice(&wrapped).unwrap();
        assert_eq!(value["ndpi"]["ONE_TWO_THREE"], "value");
        assert_eq!(
            value["ndpi"]["nested_object"]["array_value"][0]["leaf_name"],
            1
        );
        assert!(value["ndpi"].get("ONE.TWO.THREE").is_none());
    }

    #[test]
    fn validate_inner_json_rejects_invalid_fragment() {
        assert!(validate_inner_json(br#""ndpi":{"hostname":"unterminated}"#).is_none());
        assert!(validate_inner_json(b"").is_none());
    }
}
