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

#![allow(non_snake_case)]

mod ndpi;

use core::ffi::c_void;
use std::ffi::CStr;
use std::mem;
use std::os::raw::{c_char, c_int};
use std::ptr;

use std::sync::atomic::{AtomicBool, Ordering};

use ndpi::{DetectionModule, Direction, Flow, GlobalContext, LicenseType};
use suricatax80_plugin_utils as suricata;

/// Suricata configuration key selecting the nDPI usage license.
const LICENSE_CONF_KEY: &str = "ndpi.license";

/// Default nDPI license type. This keeps all dissectors enabled, as with
/// nDPI 5, and matches the ndpiReader default.
const DEFAULT_LICENSE: LicenseType = LicenseType::NotForProfit;

static mut THREAD_STORAGE_ID: suricata::ThreadStorageId = suricata::ThreadStorageId { id: -1 };
static mut FLOW_STORAGE_ID: suricata::FlowStorageId = suricata::FlowStorageId { id: -1 };
static mut NDPI_PROTOCOL_KEYWORD_ID: c_int = -1;
static mut NDPI_RISK_KEYWORD_ID: c_int = -1;
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

#[repr(C)]
struct DetectNdpiProtocolData {
    l7_protocol: ndpi::Protocol,
    negated: bool,
}

#[repr(C)]
struct DetectNdpiRiskData {
    risk_mask: ndpi::Risk,
    negated: bool,
}

fn log_notice(message: String) {
    suricata::log_message(
        suricata::SC_LOG_NOTICE,
        "ndpi-plugin",
        file!(),
        line!(),
        "ndpi",
        message,
    );
}

pub(crate) fn log_warning(message: String) {
    suricata::log_message(
        suricata::SC_LOG_WARNING,
        "ndpi-plugin",
        file!(),
        line!(),
        "ndpi",
        message,
    );
}

fn log_error(message: String) {
    suricata::log_message(
        suricata::SC_LOG_ERROR,
        "ndpi-plugin",
        file!(),
        line!(),
        "ndpi",
        message,
    );
}

fn fatal(message: String) -> ! {
    suricata::fatal_error("ndpi-plugin", message)
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

unsafe fn thread_context<'a>(tv: *const suricata::ThreadVars) -> Option<&'a mut ThreadContext> {
    if tv.is_null() {
        return None;
    }
    let ptr = suricata::ThreadGetStorageById(tv, THREAD_STORAGE_ID).cast::<ThreadContext>();
    ptr.as_mut()
}

unsafe fn flow_context<'a>(f: *const suricata::Flow) -> Option<&'a mut FlowContext> {
    if f.is_null() {
        return None;
    }
    let ptr = suricata::FlowGetStorageById(f, FLOW_STORAGE_ID).cast::<FlowContext>();
    ptr.as_mut()
}

unsafe extern "C" fn thread_storage_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr.cast::<ThreadContext>()));
    }
}

unsafe extern "C" fn flow_storage_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr.cast::<FlowContext>()));
    }
}

unsafe extern "C" fn on_flow_init(
    _tv: *mut suricata::ThreadVars,
    f: *mut suricata::Flow,
    _p: *const suricata::Packet,
    _data: *mut c_void,
) {
    if f.is_null() {
        return;
    }

    // On allocation failure the flow is left without nDPI storage and is
    // simply not inspected.
    let Some(ndpi_flow) = Flow::new() else {
        return;
    };
    let ctx = Box::new(FlowContext { ndpi_flow });
    suricata::FlowSetStorageById(f, FLOW_STORAGE_ID, Box::into_raw(ctx).cast());
}

unsafe extern "C" fn on_flow_update(
    tv: *mut suricata::ThreadVars,
    f: *mut suricata::Flow,
    p: *mut suricata::Packet,
    _data: *mut c_void,
) {
    if tv.is_null() || f.is_null() || p.is_null() {
        return;
    }

    if (*p).proto != (*f).proto {
        return;
    }

    let Some(threadctx) = thread_context(tv) else {
        return;
    };
    let Some(flowctx) = flow_context(f) else {
        return;
    };
    let Some((ip_ptr, ip_len)) = (*p).ip_packet() else {
        return;
    };

    let packet_count = (*f).todstpktcnt + (*f).tosrcpktcnt;
    flowctx.ndpi_flow.process_packet(
        &mut threadctx.ndpi,
        ip_ptr,
        ip_len,
        (*p).timestamp_millis(),
        packet_direction(&*p),
        (*f).proto,
        packet_count,
    );
}

unsafe extern "C" fn on_flow_finish(
    _tv: *mut suricata::ThreadVars,
    _f: *mut suricata::Flow,
    _data: *mut c_void,
) {
}

unsafe extern "C" fn on_thread_init(tv: *mut suricata::ThreadVars, _data: *mut c_void) {
    if tv.is_null() {
        return;
    }

    let ndpi = DetectionModule::new(LICENSE, GLOBAL_CONTEXT)
        .unwrap_or_else(|| fatal("Failed to initialize nDPI detection module".to_string()));
    let ctx = Box::new(ThreadContext { ndpi });
    suricata::ThreadSetStorageById(tv, THREAD_STORAGE_ID, Box::into_raw(ctx).cast());
}

unsafe extern "C" fn detect_ndpi_protocol_packet_match(
    _det_ctx: *mut suricata::DetectEngineThreadCtx,
    p: *mut suricata::Packet,
    _s: *const suricata::Signature,
    ctx: *const suricata::SigMatchCtx,
) -> c_int {
    if p.is_null() || ctx.is_null() {
        return 0;
    }

    let f = (*p).flow;
    let Some(flowctx) = flow_context(f) else {
        return 0;
    };
    if !flowctx.ndpi_flow.detection_completed() {
        return 0;
    }

    let data = &*(ctx.cast::<DetectNdpiProtocolData>());
    if flowctx
        .ndpi_flow
        .protocol_matches(data.l7_protocol, data.negated)
    {
        1
    } else {
        0
    }
}

fn detect_ndpi_protocol_parse(
    arg: *const c_char,
    negate: bool,
) -> Option<Box<DetectNdpiProtocolData>> {
    let l7_protocol = ndpi::parse_protocol(arg, unsafe { LICENSE });
    if l7_protocol.is_none() && !arg.is_null() {
        let name = unsafe { CStr::from_ptr(arg) }.to_string_lossy();
        log_error(format!("failure parsing nDPI protocol '{}'", name));
    }

    Some(Box::new(DetectNdpiProtocolData {
        l7_protocol: l7_protocol?,
        negated: negate,
    }))
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
    if s.is_null() || (*s).init_data.is_null() {
        return -1;
    }

    let init = &mut *(*s).init_data;
    let data = match detect_ndpi_protocol_parse(arg, init.negated) {
        Some(data) => data,
        None => return -1,
    };

    let mut tsm = init.smlists[suricata::DETECT_SM_LIST_MATCH as usize];
    while !tsm.is_null() {
        if (*tsm).type_ as c_int == NDPI_PROTOCOL_KEYWORD_ID {
            let them = &*((*tsm).ctx.cast::<DetectNdpiProtocolData>());
            if ndpi_protocol_data_has_conflicts(&data, them) {
                log_error("can't mix positive ndpi-protocol match with negated".to_string());
                return -1;
            }
        }
        tsm = (*tsm).next;
    }

    let raw = Box::into_raw(data);
    let sm = suricata::SCSigMatchAppendSMToList(
        de_ctx,
        s,
        NDPI_PROTOCOL_KEYWORD_ID as u16,
        raw.cast::<suricata::SigMatchCtx>(),
        suricata::DETECT_SM_LIST_MATCH,
    );
    if sm.is_null() {
        drop(Box::from_raw(raw));
        return -1;
    }
    0
}

unsafe extern "C" fn detect_ndpi_protocol_free(
    _de_ctx: *mut suricata::DetectEngineCtx,
    ptr: *mut c_void,
) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr.cast::<DetectNdpiProtocolData>()));
    }
}

unsafe extern "C" fn detect_ndpi_risk_packet_match(
    _det_ctx: *mut suricata::DetectEngineThreadCtx,
    p: *mut suricata::Packet,
    _s: *const suricata::Signature,
    ctx: *const suricata::SigMatchCtx,
) -> c_int {
    if p.is_null() || ctx.is_null() {
        return 0;
    }

    let f = (*p).flow;
    let Some(flowctx) = flow_context(f) else {
        return 0;
    };
    if !flowctx.ndpi_flow.detection_completed() {
        return 0;
    }

    let data = &*(ctx.cast::<DetectNdpiRiskData>());
    if flowctx.ndpi_flow.risk_matches(data.risk_mask, data.negated) {
        1
    } else {
        0
    }
}

unsafe fn detect_ndpi_risk_parse(
    arg: *const c_char,
    negate: bool,
) -> Option<Box<DetectNdpiRiskData>> {
    let risk_mask = ndpi::parse_risk(arg);
    if risk_mask.is_none() && !arg.is_null() {
        let name = CStr::from_ptr(arg).to_string_lossy();
        log_error(format!(
            "unrecognized risk '{}', please check ndpiReader -H for valid risk codes",
            name
        ));
    }

    Some(Box::new(DetectNdpiRiskData {
        risk_mask: risk_mask?,
        negated: negate,
    }))
}

fn ndpi_risk_data_has_conflicts(us: &DetectNdpiRiskData, them: &DetectNdpiRiskData) -> bool {
    us.risk_mask == them.risk_mask
}

unsafe extern "C" fn detect_ndpi_risk_setup(
    de_ctx: *mut suricata::DetectEngineCtx,
    s: *mut suricata::Signature,
    arg: *const c_char,
) -> c_int {
    if s.is_null() || (*s).init_data.is_null() {
        return -1;
    }

    let init = &mut *(*s).init_data;
    let data = match detect_ndpi_risk_parse(arg, init.negated) {
        Some(data) => data,
        None => return -1,
    };

    let mut tsm = init.smlists[suricata::DETECT_SM_LIST_MATCH as usize];
    while !tsm.is_null() {
        if (*tsm).type_ as c_int == NDPI_RISK_KEYWORD_ID {
            let them = &*((*tsm).ctx.cast::<DetectNdpiRiskData>());
            if ndpi_risk_data_has_conflicts(&data, them) {
                log_error("can't mix positive ndpi-risk match with negated".to_string());
                return -1;
            }
        }
        tsm = (*tsm).next;
    }

    let raw = Box::into_raw(data);
    let sm = suricata::SCSigMatchAppendSMToList(
        de_ctx,
        s,
        NDPI_RISK_KEYWORD_ID as u16,
        raw.cast::<suricata::SigMatchCtx>(),
        suricata::DETECT_SM_LIST_MATCH,
    );
    if sm.is_null() {
        drop(Box::from_raw(raw));
        return -1;
    }
    0
}

unsafe extern "C" fn detect_ndpi_risk_free(
    _de_ctx: *mut suricata::DetectEngineCtx,
    ptr: *mut c_void,
) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr.cast::<DetectNdpiRiskData>()));
    }
}

unsafe extern "C" fn eve_callback(
    tv: *mut suricata::ThreadVars,
    _p: *const suricata::Packet,
    f: *mut suricata::Flow,
    jb: *mut suricata::SCJsonBuilder,
    _data: *mut c_void,
) {
    if tv.is_null() || f.is_null() || jb.is_null() {
        return;
    }

    let Some(threadctx) = thread_context(tv) else {
        return;
    };
    let Some(flowctx) = flow_context(f) else {
        return;
    };
    if !flowctx.ndpi_flow.write_json(&mut threadctx.ndpi, jb)
        && !JSON_DROPPED.swap(true, Ordering::Relaxed)
    {
        log_warning(
            "nDPI produced malformed JSON for a flow, dropping its EVE object \
             (only reported once)"
                .to_string(),
        );
    }
}

unsafe fn init_keywords() {
    if suricata::sigmatch_table.is_null() {
        fatal("sigmatch_table unavailable".to_string());
    }

    NDPI_PROTOCOL_KEYWORD_ID = suricata::SCDetectHelperNewKeywordId();
    if NDPI_PROTOCOL_KEYWORD_ID < 0 {
        fatal("Failed to register ndpi-protocol keyword".to_string());
    }

    let proto = &mut *suricata::sigmatch_table.add(NDPI_PROTOCOL_KEYWORD_ID as usize);
    proto.name = b"ndpi-protocol\0".as_ptr().cast();
    proto.desc = b"match on the detected nDPI protocol\0".as_ptr().cast();
    proto.url = b"/rules/ndpi-protocol.html\0".as_ptr().cast();
    proto.Match = Some(detect_ndpi_protocol_packet_match);
    proto.Setup = Some(detect_ndpi_protocol_setup);
    proto.Free = Some(detect_ndpi_protocol_free);
    proto.flags = suricata::SIGMATCH_QUOTES_OPTIONAL | suricata::SIGMATCH_HANDLE_NEGATION;

    NDPI_RISK_KEYWORD_ID = suricata::SCDetectHelperNewKeywordId();
    if NDPI_RISK_KEYWORD_ID < 0 {
        fatal("Failed to register ndpi-risk keyword".to_string());
    }

    let risk = &mut *suricata::sigmatch_table.add(NDPI_RISK_KEYWORD_ID as usize);
    risk.name = b"ndpi-risk\0".as_ptr().cast();
    risk.desc = b"match on the detected nDPI risk\0".as_ptr().cast();
    risk.url = b"/rules/ndpi-risk.html\0".as_ptr().cast();
    risk.Match = Some(detect_ndpi_risk_packet_match);
    risk.Setup = Some(detect_ndpi_risk_setup);
    risk.Free = Some(detect_ndpi_risk_free);
    risk.flags = suricata::SIGMATCH_QUOTES_OPTIONAL | suricata::SIGMATCH_HANDLE_NEGATION;
}

fn load_license() -> LicenseType {
    let Some(value) = suricata::conf_get(LICENSE_CONF_KEY) else {
        return DEFAULT_LICENSE;
    };

    LicenseType::from_config(&value).unwrap_or_else(|| {
        fatal(format!(
            "invalid ndpi.license value '{}', expected one of: not-for-profit, \
             for-profit-lgpl, for-profit-dual-license",
            value
        ))
    })
}

unsafe extern "C" fn ndpi_init() {
    LICENSE = load_license();
    log_notice(format!("nDPI license type: {}", LICENSE.as_str()));
    if LICENSE == LicenseType::ForProfitLgpl {
        log_warning(format!(
            "ndpi.license is \"{}\": nDPI will not load its dual-licensed \
             dissectors (DHCP, DNS, QUIC and TLS as of nDPI 6.0)",
            LICENSE.as_str()
        ));
    }

    // Global context shared by the worker detection modules, see
    // DetectionModule::new().
    let g_ctx = GlobalContext::new();
    GLOBAL_CONTEXT = g_ctx;
    if g_ctx.is_none() {
        log_warning(
            "Failed to initialize the nDPI global context: \
             per-thread nDPI caches will not be shared"
                .to_string(),
        );
    }

    THREAD_STORAGE_ID = suricata::ThreadStorageRegister(
        b"ndpi\0".as_ptr().cast(),
        mem::size_of::<*mut c_void>() as u32,
        None,
        Some(thread_storage_free),
    );
    if THREAD_STORAGE_ID.id < 0 {
        fatal("Failed to register nDPI thread storage".to_string());
    }

    FLOW_STORAGE_ID = suricata::FlowStorageRegister(
        b"ndpi\0".as_ptr().cast(),
        mem::size_of::<*mut c_void>() as u32,
        None,
        Some(flow_storage_free),
    );
    if FLOW_STORAGE_ID.id < 0 {
        fatal("Failed to register nDPI flow storage".to_string());
    }

    suricata::SCFlowRegisterInitCallback(Some(on_flow_init), ptr::null_mut());
    suricata::SCFlowRegisterUpdateCallback(Some(on_flow_update), ptr::null_mut());
    suricata::SCFlowRegisterFinishCallback(Some(on_flow_finish), ptr::null_mut());
    suricata::SCThreadRegisterInitCallback(Some(on_thread_init), ptr::null_mut());
    suricata::SCEveRegisterCallback(Some(eve_callback), ptr::null_mut());

    init_keywords();

    if let Some(revision) = DetectionModule::revision() {
        log_notice(format!(
            "nDPI plugin loaded (nDPI revision: {})",
            revision.to_string_lossy()
        ));
    } else {
        log_notice("nDPI plugin loaded (nDPI revision unavailable)".to_string());
    }
}

static PLUGIN: suricata::SCPlugin = suricata::SCPlugin {
    version: suricata::SC_API_VERSION,
    suricata_version: suricata::SC_PACKAGE_VERSION.as_ptr().cast(),
    plugin_version: concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast(),
    name: b"ndpi\0".as_ptr().cast(),
    author: b"Luca Deri\0".as_ptr().cast(),
    license: b"LGPL-3.0-only AND LicenseRef-nDPI-Dual-License\0".as_ptr().cast(),
    Init: Some(ndpi_init),
};

#[no_mangle]
pub extern "C" fn SCPluginRegister() -> *mut suricata::SCPlugin {
    (&PLUGIN as *const suricata::SCPlugin).cast_mut()
}
