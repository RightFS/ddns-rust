use serde::Serialize;
use std::{collections::BTreeMap, io, net::IpAddr};

#[derive(Debug, Serialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ipv4: Vec<IpAddr>,
    pub ipv6: Vec<IpAddr>,
}

type InterfaceAddresses = BTreeMap<String, Vec<IpAddr>>;

pub fn list() -> io::Result<Vec<NetworkInterface>> {
    Ok(read_interfaces()?
        .into_iter()
        .map(|(name, mut addresses)| {
            addresses.sort_unstable();
            addresses.dedup();
            let (ipv4, ipv6) = addresses.into_iter().partition(IpAddr::is_ipv4);
            NetworkInterface { name, ipv4, ipv6 }
        })
        .collect())
}

#[cfg(unix)]
fn read_interfaces() -> io::Result<InterfaceAddresses> {
    use std::ffi::CStr;

    let mut interfaces = BTreeMap::new();
    // if_nameindex includes interfaces that do not have an IP address.
    // The OS owns the entries and their names until if_freenameindex.
    unsafe {
        let head = libc::if_nameindex();
        if head.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut entry = head;
        while !(*entry).if_name.is_null() {
            let name = CStr::from_ptr((*entry).if_name)
                .to_string_lossy()
                .into_owned();
            interfaces.insert(name, Vec::new());
            entry = entry.add(1);
        }
        libc::if_freenameindex(head);
    }
    for interface in if_addrs::get_if_addrs()? {
        let ip = interface.ip();
        interfaces.entry(interface.name).or_default().push(ip);
    }
    Ok(interfaces)
}

#[cfg(windows)]
fn read_interfaces() -> io::Result<InterfaceAddresses> {
    use std::{ffi::CStr, mem::MaybeUninit, ptr};
    use windows_sys::Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS},
        NetworkManagement::IpHelper::{
            GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
            GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
        },
        Networking::WinSock::{
            AF_INET, AF_INET6, AF_UNSPEC, IpDadStatePreferred, SOCKADDR_IN, SOCKADDR_IN6,
        },
    };

    let flags = GAA_FLAG_INCLUDE_ALL_INTERFACES
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 15_000u32;
    for _ in 0..3 {
        // Allocate storage with the alignment expected by GetAdaptersAddresses.
        let mut buffer = Vec::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::with_capacity(
            (size as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>()),
        );
        let head = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // On success, the linked lists, names and socket addresses are valid
        // while the caller's buffer lives. Copy out the names and IPs.
        unsafe {
            match GetAdaptersAddresses(AF_UNSPEC.into(), flags, ptr::null(), head, &mut size) {
                ERROR_BUFFER_OVERFLOW => continue,
                ERROR_NO_DATA => return Ok(BTreeMap::new()),
                ERROR_SUCCESS => {}
                code => return Err(io::Error::from_raw_os_error(code as i32)),
            }
            let mut interfaces = BTreeMap::new();
            let mut adapter = head;
            while let Some(entry) = adapter.as_ref() {
                adapter = entry.Next;
                let name = if entry.FriendlyName.is_null() {
                    CStr::from_ptr(entry.AdapterName.cast())
                        .to_string_lossy()
                        .into_owned()
                } else {
                    let len = (0..)
                        .take_while(|&i| *entry.FriendlyName.add(i) != 0)
                        .count();
                    String::from_utf16_lossy(std::slice::from_raw_parts(entry.FriendlyName, len))
                };
                let addresses = interfaces.entry(name).or_insert_with(Vec::new);
                let mut unicast = entry.FirstUnicastAddress;
                while let Some(address) = unicast.as_ref() {
                    unicast = address.Next;
                    let socket = address.Address.lpSockaddr;
                    // Keep Windows' previous preference for usable unicast addresses.
                    if socket.is_null() || address.DadState != IpDadStatePreferred {
                        continue;
                    }
                    match (*socket).sa_family {
                        AF_INET => {
                            let ip = (*socket.cast::<SOCKADDR_IN>()).sin_addr.S_un.S_addr;
                            addresses.push(IpAddr::from(ip.to_ne_bytes()));
                        }
                        AF_INET6 => {
                            let ip = (*socket.cast::<SOCKADDR_IN6>()).sin6_addr.u.Byte;
                            addresses.push(IpAddr::from(ip));
                        }
                        _ => {}
                    }
                }
            }
            return Ok(interfaces);
        }
    }
    Err(io::Error::from_raw_os_error(ERROR_BUFFER_OVERFLOW as i32))
}
