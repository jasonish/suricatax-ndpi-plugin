/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

use std::ffi::{CStr, CString};
use std::mem;
use std::os::raw::c_char;
use std::ptr::{self, NonNull};

use ndpi_sys as ffi;

use suricatax80_plugin_utils as suricata;
use suricatax80_plugin_utils::SCLogWarning;

/// The nDPI usage license, passed to nDPI at detection module initialization.
///
/// Starting with nDPI 6.0, some dissectors (e.g. TLS, QUIC, DNS and DHCP) are
/// dual-licensed by ntop and are only loaded when nDPI is used in a
/// not-for-profit project or under a commercial license from ntop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LicenseType {
    /// Not-for-profit use: LGPL and dual-licensed dissectors are enabled.
    NotForProfit,
    /// For-profit use without an ntop license: only LGPL dissectors are
    /// enabled.
    ForProfitLgpl,
    /// For-profit use with an ntop license: all dissectors are enabled.
    ForProfitDualLicense,
}

impl LicenseType {
    pub fn from_config(value: &str) -> Option<Self> {
        match value {
            "not-for-profit" => Some(Self::NotForProfit),
            "for-profit-lgpl" => Some(Self::ForProfitLgpl),
            "for-profit-dual-license" => Some(Self::ForProfitDualLicense),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotForProfit => "not-for-profit",
            Self::ForProfitLgpl => "for-profit-lgpl",
            Self::ForProfitDualLicense => "for-profit-dual-license",
        }
    }

    fn as_ffi(self) -> ffi::ndpi_license_type {
        match self {
            Self::NotForProfit => ffi::ndpi_license_type_NDPI_LICENSE_NOT_FOR_PROFIT_LGPL,
            Self::ForProfitLgpl => ffi::ndpi_license_type_NDPI_LICENSE_FOR_PROFIT_LGPL,
            Self::ForProfitDualLicense => {
                ffi::ndpi_license_type_NDPI_LICENSE_FOR_PROFIT_DUAL_LICENSE
            }
        }
    }
}

/// The direction of a packet within its flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Unknown,
    ToServer,
    ToClient,
}

impl Direction {
    fn as_ffi(self) -> u8 {
        (match self {
            Self::Unknown => ffi::NDPI_IN_PKT_DIR_UNKNOWN,
            Self::ToServer => ffi::NDPI_IN_PKT_DIR_C_TO_S,
            Self::ToClient => ffi::NDPI_IN_PKT_DIR_S_TO_C,
        }) as u8
    }
}

/// nDPI correlates flows through LRU caches (DNS to TLS, STUN to RTP, ...)
/// that are private to a detection module unless made global through a
/// shared context. Suricata spreads a host's flows over all its workers, so
/// without sharing, a correlation never leaves the worker that saw the first
/// flow.
const SHARED_LRU_CACHES: &[&[u8]] = &[
    b"lru.ookla.scope\0",
    b"lru.bittorrent.scope\0",
    b"lru.stun.scope\0",
    b"lru.tls_cert.scope\0",
    b"lru.mining.scope\0",
    b"lru.msteams.scope\0",
    b"lru.fpc_dns.scope\0",
    b"lru.signal.scope\0",
];

/// An nDPI global context, shared by the per-thread detection modules.
///
/// There is no plugin deinit hook, so it is never released.
#[derive(Clone, Copy)]
pub struct GlobalContext {
    ptr: NonNull<ffi::ndpi_global_context>,
}

impl GlobalContext {
    pub fn new() -> Option<Self> {
        let ptr = unsafe { ffi::ndpi_global_init() };
        Some(Self {
            ptr: NonNull::new(ptr)?,
        })
    }
}

pub struct DetectionModule {
    ptr: NonNull<ffi::ndpi_detection_module_struct>,
}

// SAFETY: A detection module is owned exclusively and is only used from one
// thread at a time. It is created in Suricata's thread init callback and
// stored in that thread's storage.
unsafe impl Send for DetectionModule {}

impl DetectionModule {
    /// Allocate and finalize a detection module.
    ///
    /// Worker modules share their LRU caches through `g_ctx`; the throwaway
    /// modules used while parsing rules don't need to. nDPI creates a shared
    /// cache on the first finalization without locking, which is fine as
    /// Suricata runs thread init callbacks sequentially.
    pub fn new(license: LicenseType, g_ctx: Option<GlobalContext>) -> Option<Self> {
        unsafe {
            let g_ctx_ptr = g_ctx.map_or(ptr::null_mut(), |g_ctx| g_ctx.ptr.as_ptr());
            let ptr = ffi::ndpi_init_detection_module(g_ctx_ptr, license.as_ffi());
            let ptr = NonNull::new(ptr)?;

            if g_ctx.is_some() {
                for param in SHARED_LRU_CACHES {
                    let rc = ffi::ndpi_set_config(
                        ptr.as_ptr(),
                        ptr::null(),
                        param.as_ptr().cast(),
                        b"1\0".as_ptr().cast(),
                    );
                    if rc != ffi::ndpi_cfg_error_NDPI_CFG_OK {
                        let param = CStr::from_bytes_with_nul(param)
                            .map(|p| p.to_string_lossy())
                            .unwrap_or_default();
                        SCLogWarning!(
                            "Failed to share the nDPI \"{}\" cache between threads",
                            param
                        );
                    }
                }
            }

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

    #[allow(clippy::too_many_arguments)]
    pub fn process_packet(
        &mut self,
        module: &mut DetectionModule,
        packet: *const u8,
        packet_len: u16,
        time_ms: u64,
        direction: Direction,
        l4_proto: u8,
        packet_count: u32,
    ) {
        if self.detection_completed || packet.is_null() || packet_len == 0 {
            return;
        }

        // Whether the flow beginning was seen is left unknown, as the flow
        // API exposes no reliable flag for it.
        let mut input_info = ffi::ndpi_flow_input_info {
            in_pkt_dir: direction.as_ffi(),
            seen_flow_beginning: ffi::NDPI_FLOW_BEGINNING_UNKNOWN as u8,
        };

        unsafe {
            self.detected_l7_protocol = ffi::ndpi_detection_process_packet(
                module.as_ptr(),
                self.ptr.as_ptr(),
                packet,
                packet_len,
                time_ms,
                &mut input_info,
            );

            let state = self.detected_l7_protocol.state;
            if classification_final(state, self.ptr.as_ref()) {
                self.detection_completed = true;
            } else {
                // Stop feeding nDPI after a few packets, taking its best
                // guess for flows it could not classify.
                let max_num_pkts = if l4_proto == suricata::IPPROTO_UDP {
                    8
                } else {
                    24
                };
                if packet_count > max_num_pkts {
                    if !is_classified(state) {
                        self.detected_l7_protocol =
                            ffi::ndpi_detection_giveup(module.as_ptr(), self.ptr.as_ptr());
                    }
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

    /// Add the nDPI JSON for this flow to `jb`.
    ///
    /// Returns false if nDPI produced malformed JSON, which is then dropped
    /// instead of being added to the EVE record. nDPI 6.0 has been seen
    /// corrupting its output when escaping non-printable characters.
    pub unsafe fn write_json(
        &mut self,
        module: &mut DetectionModule,
        jb: *mut suricata::SCJsonBuilder,
    ) -> bool {
        if jb.is_null() {
            return true;
        }

        let mut serializer: ffi::ndpi_serializer = mem::zeroed();
        if ffi::ndpi_init_serializer(
            &mut serializer,
            ffi::ndpi_serialization_format_ndpi_serialization_format_inner_json,
        ) != 0
        {
            return true;
        }

        ffi::ndpi_dpi2json(
            module.as_ptr(),
            self.ptr.as_ptr(),
            self.detected_l7_protocol,
            &mut serializer,
        );

        let mut valid = true;
        let mut buffer_len = 0;
        let buffer = ffi::ndpi_serializer_get_buffer(&mut serializer, &mut buffer_len);
        if !buffer.is_null() && buffer_len > 0 {
            let buffer = std::slice::from_raw_parts(buffer.cast::<u8>(), buffer_len as usize);
            // An empty fragment is valid, there is just nothing to add.
            if !buffer.iter().all(u8::is_ascii_whitespace) {
                valid = match validate_inner_json(buffer) {
                    Some(formatted) => suricata::scjb_set_formatted(jb, formatted.as_ptr()),
                    None => false,
                };
            }
        }

        ffi::ndpi_term_serializer(&mut serializer);
        valid
    }
}

fn is_classified(state: ffi::ndpi_classification_state) -> bool {
    state == ffi::ndpi_classification_state_NDPI_STATE_CLASSIFIED
        || state == ffi::ndpi_classification_state_NDPI_STATE_MONITORING
}

/// Whether nDPI reached a final classification for the flow. Once it has,
/// the plugin stops feeding it packets and the keywords start matching.
///
/// `NDPI_STATE_CLASSIFIED` with no extra dissection pending is final, as in
/// nDPI's ndpiReader. `NDPI_STATE_MONITORING` is treated as final too: the
/// classification will not change and nDPI would only extract more
/// metadata, so stopping there bounds the per packet cost at the expense of
/// that metadata.
fn classification_final(
    state: ffi::ndpi_classification_state,
    flow: &ffi::ndpi_flow_struct,
) -> bool {
    state == ffi::ndpi_classification_state_NDPI_STATE_MONITORING
        || (state == ffi::ndpi_classification_state_NDPI_STATE_CLASSIFIED
            && flow.extra_packets_func.is_none())
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

// SAFETY: An nDPI flow is owned exclusively by its Suricata flow's storage,
// which is only used by one thread at a time under the flow lock.
unsafe impl Send for Flow {}

impl Drop for Flow {
    fn drop(&mut self) {
        unsafe {
            ffi::ndpi_flow_free(self.ptr.as_ptr().cast());
        }
    }
}

pub fn parse_protocol(
    name: *const c_char,
    license: LicenseType,
) -> Option<ffi::ndpi_master_app_protocol> {
    if name.is_null() {
        return None;
    }

    let mut module = DetectionModule::new(license, None)?;
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
    use super::{classification_final, ffi, is_classified, validate_inner_json, LicenseType};

    unsafe extern "C" fn extra_packets(
        _ndpi: *mut ffi::ndpi_detection_module_struct,
        _flow: *mut ffi::ndpi_flow_struct,
    ) -> std::os::raw::c_int {
        1
    }

    #[test]
    fn classification_final_states() {
        let mut flow: Box<ffi::ndpi_flow_struct> = Box::new(unsafe { std::mem::zeroed() });

        assert!(!classification_final(
            ffi::ndpi_classification_state_NDPI_STATE_INSPECTING,
            &flow
        ));
        assert!(!classification_final(
            ffi::ndpi_classification_state_NDPI_STATE_PARTIAL,
            &flow
        ));
        assert!(classification_final(
            ffi::ndpi_classification_state_NDPI_STATE_MONITORING,
            &flow
        ));
        assert!(classification_final(
            ffi::ndpi_classification_state_NDPI_STATE_CLASSIFIED,
            &flow
        ));

        // Classified, but extra dissection is still pending.
        flow.extra_packets_func = Some(extra_packets);
        assert!(!classification_final(
            ffi::ndpi_classification_state_NDPI_STATE_CLASSIFIED,
            &flow
        ));
        assert!(classification_final(
            ffi::ndpi_classification_state_NDPI_STATE_MONITORING,
            &flow
        ));

        for (state, classified) in [
            (ffi::ndpi_classification_state_NDPI_STATE_INSPECTING, false),
            (ffi::ndpi_classification_state_NDPI_STATE_PARTIAL, false),
            (ffi::ndpi_classification_state_NDPI_STATE_MONITORING, true),
            (ffi::ndpi_classification_state_NDPI_STATE_CLASSIFIED, true),
        ] {
            assert_eq!(is_classified(state), classified);
        }
    }

    #[test]
    fn license_type_from_config() {
        for license in [
            LicenseType::NotForProfit,
            LicenseType::ForProfitLgpl,
            LicenseType::ForProfitDualLicense,
        ] {
            assert_eq!(LicenseType::from_config(license.as_str()), Some(license));
        }
        assert_eq!(LicenseType::from_config("for-profit"), None);
        assert_eq!(LicenseType::from_config(""), None);
    }

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
    fn validate_inner_json_preserves_field_order() {
        let formatted = validate_inner_json(
            br#""ndpi":{"proto":"TLS","a.b":1,"breed":"Safe","category":"Web"}"#,
        )
        .unwrap();
        assert_eq!(
            formatted.to_str().unwrap(),
            r#""ndpi":{"proto":"TLS","a_b":1,"breed":"Safe","category":"Web"}"#
        );
    }

    #[test]
    fn validate_inner_json_rejects_invalid_fragment() {
        assert!(validate_inner_json(br#""ndpi":{"hostname":"unterminated}"#).is_none());
        assert!(validate_inner_json(b"").is_none());
    }
}
