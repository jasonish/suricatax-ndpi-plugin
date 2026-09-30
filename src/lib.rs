// SPDX-FileCopyrightText: 2026 Open Information Security Foundation
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(non_snake_case)]

mod ndpi;

use core::ffi::c_void;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use ndpi::{DetectionModule, Direction, Flow, GlobalContext, LicenseType};
use suricatax80_plugin_utils as suricata;
use suricatax80_plugin_utils::{SCFatalError, SCLogError, SCLogNotice, SCLogWarning};

/// Suricata configuration key selecting the nDPI usage license.
const LICENSE_CONF_KEY: &str = "ndpi.license";

/// Default nDPI license type. This keeps all dissectors enabled, as with
/// nDPI 5, and matches the ndpiReader default.
const DEFAULT_LICENSE: LicenseType = LicenseType::NotForProfit;

static THREAD_STORAGE: OnceLock<suricata::ThreadStorage<ThreadContext>> = OnceLock::new();
static FLOW_STORAGE: OnceLock<suricata::FlowStorage<FlowContext>> = OnceLock::new();
static NDPI_PROTOCOL_KEYWORD_ID: OnceLock<u16> = OnceLock::new();
static NDPI_RISK_KEYWORD_ID: OnceLock<u16> = OnceLock::new();
static mut LICENSE: LicenseType = DEFAULT_LICENSE;
static mut GLOBAL_CONTEXT: Option<GlobalContext> = None;
/// Set once nDPI produced malformed JSON, so it is only reported once.
static JSON_DROPPED: AtomicBool = AtomicBool::new(false);

struct ThreadContext {
    ndpi: DetectionModule,
}

struct FlowContext {
    ndpi_flow: Flow,
}

struct DetectNdpiProtocolData {
    l7_protocol: ndpi::Protocol,
    negated: bool,
}

struct DetectNdpiRiskData {
    risk_mask: ndpi::Risk,
    negated: bool,
}

/// The direction of the packet within its flow.
fn packet_direction(p: &suricata::Packet) -> Direction {
    if p.is_toserver() {
        Direction::ToServer
    } else if p.is_toclient() {
        Direction::ToClient
    } else {
        Direction::Unknown
    }
}

/// The thread storage, registered in plugin init.
fn thread_storage() -> Option<suricata::ThreadStorage<ThreadContext>> {
    THREAD_STORAGE.get().copied()
}

/// The flow storage, registered in plugin init.
fn flow_storage() -> Option<suricata::FlowStorage<FlowContext>> {
    FLOW_STORAGE.get().copied()
}

/// The nDPI context of the flow `f`, if any.
///
/// # Safety
///
/// `f` must be null or a flow passed by Suricata, and the returned reference
/// must not outlive the callback it was obtained in.
unsafe fn flow_context<'a>(f: *const suricata::Flow) -> Option<&'a FlowContext> {
    flow_storage()?.get(f.as_ref()?)
}

unsafe extern "C" fn on_flow_init(
    _tv: *mut suricata::ThreadVars,
    f: *mut suricata::Flow,
    _p: *const suricata::Packet,
    _data: *mut c_void,
) {
    let (Some(f), Some(storage)) = (f.as_mut(), flow_storage()) else {
        return;
    };

    // On allocation failure the flow is left without nDPI storage and is
    // simply not inspected.
    let Some(ndpi_flow) = Flow::new() else {
        return;
    };
    let _ = storage.set(f, FlowContext { ndpi_flow });
}

unsafe extern "C" fn on_flow_update(
    tv: *mut suricata::ThreadVars,
    f: *mut suricata::Flow,
    p: *mut suricata::Packet,
    _data: *mut c_void,
) {
    let (Some(tv), Some(f), Some(p)) = (tv.as_mut(), f.as_mut(), p.as_ref()) else {
        return;
    };

    if p.proto != f.proto {
        return;
    }

    let (Some(thread_storage), Some(flow_storage)) = (thread_storage(), flow_storage()) else {
        return;
    };
    let l4_proto = f.proto;
    let packet_count = f.todstpktcnt + f.tosrcpktcnt;
    let Some(threadctx) = thread_storage.get_mut(tv) else {
        return;
    };
    let Some(flowctx) = flow_storage.get_mut(f) else {
        return;
    };
    let Some((ip_ptr, ip_len)) = p.ip_packet() else {
        return;
    };

    flowctx.ndpi_flow.process_packet(
        &mut threadctx.ndpi,
        ip_ptr,
        ip_len,
        p.timestamp_millis(),
        packet_direction(p),
        l4_proto,
        packet_count,
    );
}

unsafe extern "C" fn on_thread_init(tv: *mut suricata::ThreadVars, _data: *mut c_void) {
    let (Some(tv), Some(storage)) = (tv.as_mut(), thread_storage()) else {
        return;
    };

    let ndpi = DetectionModule::new(LICENSE, GLOBAL_CONTEXT)
        .unwrap_or_else(|| SCFatalError!("Failed to initialize nDPI detection module"));
    if let Err(err) = storage.set(tv, ThreadContext { ndpi }) {
        SCFatalError!("Failed to set nDPI thread storage: {}", err);
    }
}

unsafe extern "C" fn detect_ndpi_protocol_packet_match(
    _det_ctx: *mut suricata::DetectEngineThreadCtx,
    p: *mut suricata::Packet,
    _s: *const suricata::Signature,
    ctx: *const suricata::SigMatchCtx,
) -> c_int {
    let (Some(p), Some(data)) = (p.as_ref(), ctx.cast::<DetectNdpiProtocolData>().as_ref()) else {
        return 0;
    };
    let Some(flowctx) = flow_context(p.flow) else {
        return 0;
    };
    if !flowctx.ndpi_flow.detection_completed() {
        return 0;
    }

    flowctx
        .ndpi_flow
        .protocol_matches(data.l7_protocol, data.negated) as c_int
}

fn detect_ndpi_protocol_parse(arg: *const c_char, negate: bool) -> Option<DetectNdpiProtocolData> {
    let l7_protocol = ndpi::parse_protocol(arg, unsafe { LICENSE });
    if l7_protocol.is_none() && !arg.is_null() {
        let name = unsafe { CStr::from_ptr(arg) }.to_string_lossy();
        SCLogError!("failure parsing nDPI protocol '{}'", name);
    }

    Some(DetectNdpiProtocolData {
        l7_protocol: l7_protocol?,
        negated: negate,
    })
}

fn ndpi_protocol_data_has_conflicts(
    us: &DetectNdpiProtocolData,
    them: &DetectNdpiProtocolData,
) -> bool {
    if them.negated ^ us.negated {
        return true;
    }
    if !us.negated {
        return true;
    }
    if ndpi::protocols_equal(us.l7_protocol, them.l7_protocol, true) {
        return true;
    }
    false
}

unsafe extern "C" fn detect_ndpi_protocol_setup(
    de_ctx: *mut suricata::DetectEngineCtx,
    s: *mut suricata::Signature,
    arg: *const c_char,
) -> c_int {
    let Some(&keyword_id) = NDPI_PROTOCOL_KEYWORD_ID.get() else {
        return -1;
    };
    let Some(data) = detect_ndpi_protocol_parse(arg, suricata::signature_is_negated(s)) else {
        return -1;
    };

    for sm in suricata::signature_sigmatches(s, suricata::DETECT_SM_LIST_MATCH) {
        if let Some(them) = sm.context_as::<DetectNdpiProtocolData>(keyword_id) {
            if ndpi_protocol_data_has_conflicts(&data, them) {
                SCLogError!("can't mix positive ndpi-protocol match with negated");
                return -1;
            }
        }
    }

    match suricata::signature_append_sigmatch(
        de_ctx,
        s,
        keyword_id,
        Box::new(data),
        suricata::DETECT_SM_LIST_MATCH,
    ) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

unsafe extern "C" fn detect_ndpi_risk_packet_match(
    _det_ctx: *mut suricata::DetectEngineThreadCtx,
    p: *mut suricata::Packet,
    _s: *const suricata::Signature,
    ctx: *const suricata::SigMatchCtx,
) -> c_int {
    let (Some(p), Some(data)) = (p.as_ref(), ctx.cast::<DetectNdpiRiskData>().as_ref()) else {
        return 0;
    };
    let Some(flowctx) = flow_context(p.flow) else {
        return 0;
    };
    if !flowctx.ndpi_flow.detection_completed() {
        return 0;
    }

    flowctx.ndpi_flow.risk_matches(data.risk_mask, data.negated) as c_int
}

unsafe fn detect_ndpi_risk_parse(arg: *const c_char, negate: bool) -> Option<DetectNdpiRiskData> {
    let risk_mask = ndpi::parse_risk(arg);
    if risk_mask.is_none() && !arg.is_null() {
        let name = CStr::from_ptr(arg).to_string_lossy();
        SCLogError!(
            "unrecognized risk '{}', please check ndpiReader -H for valid risk codes",
            name
        );
    }

    Some(DetectNdpiRiskData {
        risk_mask: risk_mask?,
        negated: negate,
    })
}

fn ndpi_risk_data_has_conflicts(us: &DetectNdpiRiskData, them: &DetectNdpiRiskData) -> bool {
    us.risk_mask == them.risk_mask
}

unsafe extern "C" fn detect_ndpi_risk_setup(
    de_ctx: *mut suricata::DetectEngineCtx,
    s: *mut suricata::Signature,
    arg: *const c_char,
) -> c_int {
    let Some(&keyword_id) = NDPI_RISK_KEYWORD_ID.get() else {
        return -1;
    };
    let Some(data) = detect_ndpi_risk_parse(arg, suricata::signature_is_negated(s)) else {
        return -1;
    };

    for sm in suricata::signature_sigmatches(s, suricata::DETECT_SM_LIST_MATCH) {
        if let Some(them) = sm.context_as::<DetectNdpiRiskData>(keyword_id) {
            if ndpi_risk_data_has_conflicts(&data, them) {
                SCLogError!("can't mix positive ndpi-risk match with negated");
                return -1;
            }
        }
    }

    match suricata::signature_append_sigmatch(
        de_ctx,
        s,
        keyword_id,
        Box::new(data),
        suricata::DETECT_SM_LIST_MATCH,
    ) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

unsafe extern "C" fn eve_callback(
    tv: *mut suricata::ThreadVars,
    _p: *const suricata::Packet,
    f: *mut suricata::Flow,
    jb: *mut suricata::SCJsonBuilder,
    _data: *mut c_void,
) {
    let (Some(tv), Some(f)) = (tv.as_mut(), f.as_mut()) else {
        return;
    };
    if jb.is_null() {
        return;
    }

    let (Some(thread_storage), Some(flow_storage)) = (thread_storage(), flow_storage()) else {
        return;
    };
    let Some(threadctx) = thread_storage.get_mut(tv) else {
        return;
    };
    let Some(flowctx) = flow_storage.get_mut(f) else {
        return;
    };
    if !flowctx.ndpi_flow.write_json(&mut threadctx.ndpi, jb)
        && !JSON_DROPPED.swap(true, Ordering::Relaxed)
    {
        SCLogWarning!(
            "nDPI produced malformed JSON for a flow, dropping its EVE object \
             (only reported once)"
        );
    }
}

fn init_keywords() {
    let flags = suricata::SIGMATCH_QUOTES_OPTIONAL | suricata::SIGMATCH_HANDLE_NEGATION;

    let protocol = suricata::PacketKeyword {
        name: b"ndpi-protocol\0",
        description: b"match on the detected nDPI protocol\0",
        url: b"/rules/ndpi-protocol.html\0",
        flags,
        setup: detect_ndpi_protocol_setup,
        free: suricata::sigmatch_ctx_free::<DetectNdpiProtocolData>,
        packet_match: detect_ndpi_protocol_packet_match,
    };
    let id = suricata::register_packet_keyword(&protocol)
        .unwrap_or_else(|err| SCFatalError!("Failed to register ndpi-protocol keyword: {}", err));
    let _ = NDPI_PROTOCOL_KEYWORD_ID.set(id);

    let risk = suricata::PacketKeyword {
        name: b"ndpi-risk\0",
        description: b"match on the detected nDPI risk\0",
        url: b"/rules/ndpi-risk.html\0",
        flags,
        setup: detect_ndpi_risk_setup,
        free: suricata::sigmatch_ctx_free::<DetectNdpiRiskData>,
        packet_match: detect_ndpi_risk_packet_match,
    };
    let id = suricata::register_packet_keyword(&risk)
        .unwrap_or_else(|err| SCFatalError!("Failed to register ndpi-risk keyword: {}", err));
    let _ = NDPI_RISK_KEYWORD_ID.set(id);
}

fn load_license() -> LicenseType {
    let Some(value) = suricata::conf_get(LICENSE_CONF_KEY) else {
        return DEFAULT_LICENSE;
    };

    LicenseType::from_config(&value).unwrap_or_else(|| {
        SCFatalError!(
            "invalid ndpi.license value '{}', expected one of: not-for-profit, \
             for-profit-lgpl, for-profit-dual-license",
            value
        )
    })
}

unsafe extern "C" fn ndpi_init() {
    LICENSE = load_license();
    SCLogNotice!("nDPI license type: {}", LICENSE.as_str());
    if LICENSE == LicenseType::ForProfitLgpl {
        SCLogWarning!(
            "ndpi.license is \"{}\": nDPI will not load its dual-licensed \
             dissectors (DHCP, DNS, QUIC and TLS as of nDPI 6.0)",
            LICENSE.as_str()
        );
    }

    // Global context shared by the worker detection modules, see
    // DetectionModule::new().
    let g_ctx = GlobalContext::new();
    GLOBAL_CONTEXT = g_ctx;
    if g_ctx.is_none() {
        SCLogWarning!(
            "Failed to initialize the nDPI global context: \
             per-thread nDPI caches will not be shared"
        );
    }

    let thread_storage = suricata::ThreadStorage::register("ndpi")
        .unwrap_or_else(|err| SCFatalError!("Failed to register nDPI thread storage: {}", err));
    let _ = THREAD_STORAGE.set(thread_storage);

    let flow_storage = suricata::FlowStorage::register("ndpi")
        .unwrap_or_else(|err| SCFatalError!("Failed to register nDPI flow storage: {}", err));
    let _ = FLOW_STORAGE.set(flow_storage);

    suricata::SCFlowRegisterInitCallback(Some(on_flow_init), ptr::null_mut());
    suricata::SCFlowRegisterUpdateCallback(Some(on_flow_update), ptr::null_mut());
    suricata::SCThreadRegisterInitCallback(Some(on_thread_init), ptr::null_mut());
    suricata::SCEveRegisterCallback(Some(eve_callback), ptr::null_mut());

    init_keywords();

    if let Some(revision) = DetectionModule::revision() {
        SCLogNotice!(
            "nDPI plugin loaded (nDPI revision: {})",
            revision.to_string_lossy()
        );
    } else {
        SCLogNotice!("nDPI plugin loaded (nDPI revision unavailable)");
    }
}

suricata::plugin!(
    name: "ndpi",
    author: "Jason Ish",
    license: "LGPL-3.0-only AND LicenseRef-nDPI-Dual-License",
    init: ndpi_init,
);
