//! What drivers call on the Plug and Play manager.

#![allow(non_snake_case)]

use super::engine;
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::pnp::BUS_RELATIONS;

/// [`IoInvalidateDeviceRelations`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioinvalidatedevicerelations):
/// the relations of `device`, a physical device object, have changed.
/// For `BusRelations` the device is asked for its children again, by a
/// worker thread, some time after this returns; callable at
/// `DISPATCH_LEVEL`. A device that is not started when its turn comes
/// is not asked: it is asked when it starts.
///
/// The other relation types change nothing NK keeps: ejection, power
/// and removal relations are asked for when a device is ejected,
/// powered or removed, none of which NK does.
///
/// # Safety
/// `device` is a live device object.
pub unsafe extern "C" fn IoInvalidateDeviceRelations(device: *mut DEVICE_OBJECT, relation: u32) {
    // SAFETY: per the contract.
    unsafe {
        crate::io::device::check(device, "IoInvalidateDeviceRelations");
        if relation == BUS_RELATIONS {
            engine::enumerate_later(device);
        }
    }
}
