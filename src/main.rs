// ******************************************************************
// udp-broadcast-relay-rs
//    Relays UDP broadcasts to other networks, forging the sender address.
//
// Copyright (c) 2025 UDP Broadcast Relay (Rust) Contributors
//   <github.com/blackholefox/udp-broadcast-relay-rs>
// Copyright (c) 2017 UDP Broadcast Relay Redux Contributors
//   <github.com/udp-redux/udp-broadcast-relay-redux>
// Copyright (c) 2003 Joachim Breitner <mail@joachim-breitner.de>
// Copyright (C) 2002 Nathan O'Sullivan
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// ******************************************************************
//

#![warn(clippy::undocumented_unsafe_blocks)]
// macOS and FreeBSD are similar to an extent so this should work fine enough.
#[cfg(not(any(target_os = "freebsd", target_os = "macos", target_os = "linux")))]
compile_error!("unsupported platform");

use anyhow::Context;
use clap::Parser;
use libc::msghdr;
use socket2::{SockAddr, Socket};
use std::{
    io,
    mem::{self, MaybeUninit},
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::AsRawFd,
    ptr::NonNull,
};

const IPHEADER_LEN: u16 = 20;
const UDPHEADER_LEN: u16 = 8;
const HEADER_LEN: u16 = IPHEADER_LEN + UDPHEADER_LEN;
const TTL_ID_OFFSET: u8 = 64;

const CONTROL_BUFFER_SIZE: usize = 16384;

const GRAM_BUFFER_SIZE: usize = 4096;
const GRAM_BUFFER: [u8; GRAM_BUFFER_SIZE] = {
    const START_LEN: usize = 38;
    #[rustfmt::skip]
    const GRAM_START: [u8; START_LEN] = [
        0x45,    0x00,    0x00,    0x26,
        0x12,    0x34,    0x00,    0x00,
        0xFF,    0x11,    0,    0,
        0,    0,    0,    0,
        0,    0,    0,    0,
        0,    0,    0,    0,
        0x00,    0x12,    0x00,    0x00,
        b'1',b'2',b'3',b'4',b'5',b'6',b'7',b'8',b'9',b'0',
    ];

    #[repr(C)]
    struct BufferParts {
        defined: [u8; START_LEN],
        scratch: [u8; GRAM_BUFFER_SIZE - START_LEN],
    }

    let init = BufferParts {
        defined: GRAM_START,
        scratch: [0u8; GRAM_BUFFER_SIZE - START_LEN],
    };

    const { assert!(size_of::<BufferParts>() == GRAM_BUFFER_SIZE) };
    // SAFETY: `BufferParts` is always the same size as the array being defined.
    unsafe { mem::transmute(init) }
};

#[derive(Debug)]
struct MachineIterface {
    destination_addr: Ipv4Addr,
    interface_addr: Ipv4Addr,
    ifindex: i32,
    socket: Socket,
}

impl PartialEq for MachineIterface {
    fn eq(&self, other: &Self) -> bool {
        self.destination_addr == other.destination_addr
            && self.interface_addr == other.interface_addr
            && self.ifindex == other.ifindex
    }
}

// macOS defines are at /usr/include/sys/sockio.h.

#[cfg(not(target_vendor = "apple"))]
const SIOCGIFFLAGS: u64 = libc::SIOCGIFFLAGS;
#[cfg(target_vendor = "apple")]
const SIOCGIFFLAGS: u64 = 17;

#[cfg(not(target_vendor = "apple"))]
const SIOCGIFADDR: u64 = libc::SIOCGIFADDR;
#[cfg(target_vendor = "apple")]
const SIOCGIFADDR: u64 = 33;

#[cfg(not(target_vendor = "apple"))]
const SIOCGIFDSTADDR: u64 = libc::SIOCGIFDSTADDR;
#[cfg(target_vendor = "apple")]
const SIOCGIFDSTADDR: u64 = 34;

#[cfg(not(target_vendor = "apple"))]
const SIOCGIFBRDADDR: u64 = libc::SIOCGIFBRDADDR;
#[cfg(target_vendor = "apple")]
const SIOCGIFBRDADDR: u64 = 35;

#[cfg(not(target_os = "linux"))]
const IOCTL_GROUP: u8 = b'i';

const HELP_ABOUT: &str = "
This program listens for broadcast packets on the specified UDP port
and then forwards them to each other given interface. Packets are sent
such that they appear to have come from the original broadcaster, resp.
from the spoofing IP in case -s is used. When using multiple instances
for the same port on the same network, they must have a different id.
";

#[derive(Parser)]
#[command(version, about = HELP_ABOUT, long_about = None)]
struct CliRelay {
    #[arg(short, long, default_value_t = false, help = "enables debugging")]
    debugging: bool,
    #[arg(
        short,
        long,
        default_value_t = false,
        help = "forces forking to background"
    )]
    fork_to_background: bool,
    /// `spoof_addr`
    #[arg(
        short,
        help = r#"
        sets the source IP of forwarded packets; otherwise the original sender's address is used.
        Setting to 1.1.1.1 uses outgoing interface address and broadcast port (helps in some rare cases).
        Setting to 1.1.1.2 uses outgoing interface address and source port (helps in some rare cases).
        "#
    )]
    source_ip: Option<Ipv4Addr>,
    /// `target_addr_override`
    #[arg(
        short,
        help = r#"
        sets the destination IP of forwarded packets; otherwise the original target is used.
        Setting to 255.255.255.255 uses the broadcast address of the outgoing interface.
        "#
    )]
    target_ip: Option<Ipv4Addr>,
    #[arg(long, help = "udp-port")]
    port: u16,
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=99))]
    id: u8,
    #[arg(long = "dev", value_parser = parse_interface, help = "dev1")]
    interface_names: Vec<ValidatedInterfaceName>,
    #[arg(short, long = "mulitcast", help = "ip")]
    #[arg()]
    multicast_ips: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone)]
struct ValidatedInterfaceName([u8; libc::IFNAMSIZ]);

impl ValidatedInterfaceName {
    fn as_str(&self) -> &str {
        let len = self.0.iter().copied().position(|b| b == 0).unwrap();
        core::str::from_utf8(&self.0[..len]).unwrap()
    }
}

fn parse_interface(value: &str) -> Result<ValidatedInterfaceName, io::Error> {
    if value.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "value with interior NUL",
        ));
    }

    if value.len() + 1 > libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "value too long",
        ));
    }

    let mut name = [0u8; libc::IFNAMSIZ];
    name[..value.len()].copy_from_slice(value.as_bytes());

    Ok(ValidatedInterfaceName(name))
}

#[derive(Clone, Copy)]
enum SpoofFromAddrMode {
    BroadcastPort,
    SourcePort,
    Other(Ipv4Addr),
}

#[derive(Clone, Copy)]
enum SpoofDestAddrMode {
    NewInterfaceBroadcast,
    Other(Ipv4Addr),
}

fn ip_from_raw(raw: libc::in_addr) -> Ipv4Addr {
    Ipv4Addr::from_bits(u32::from_be(raw.s_addr))
}

fn main() {
    let args = CliRelay::parse();

    let mut log_builder = env_logger::Builder::from_default_env();
    if args.debugging {
        log_builder.filter_level(log::LevelFilter::Debug);
    }
    log_builder.format_module_path(false);
    log_builder.format_target(false);
    log_builder.init();

    if args.debugging {
        log::debug!("Debugging Mode enabled");
    }
    if args.fork_to_background {
        log::debug!("Forking Mode enabled");
    }

    let from_spoof_mode = match args.source_ip {
        Some(source) => {
            // INADDR_NONE is a valid IP address (-1 = 255.255.255.255),
            // so inet_pton() would be a better choice. But in this case it
            // does not matter.
            if source == Ipv4Addr::BROADCAST {
                log::error!("invalid source IP address: {source}");
                return;
            }

            log::debug!("Outgoing source IP set to {source}");

            Some(match source {
                _ if source == Ipv4Addr::new(1, 1, 1, 1) => SpoofFromAddrMode::BroadcastPort,
                _ if source == Ipv4Addr::new(1, 1, 1, 2) => SpoofFromAddrMode::SourcePort,
                source => SpoofFromAddrMode::Other(source),
            })
        }
        None => None,
    };

    let dest_spoof_mode = match args.target_ip {
        Some(target) => {
            log::debug!("Outgoing target IP set to {target}");
            Some(if target == Ipv4Addr::BROADCAST {
                SpoofDestAddrMode::NewInterfaceBroadcast
            } else {
                SpoofDestAddrMode::Other(target)
            })
        }
        None => None,
    };

    log::debug!("ID set to {}", args.id);
    log::info!("Port set to {}", args.port);

    let ttl = args.id + TTL_ID_OFFSET;
    let port = args.port;

    log::debug!("ID: {} (ttl: {ttl}), Port {}", args.id, port);

    let interfaces = discover_local_interfaces(&args.interface_names, ttl).unwrap();
    let listener = setup_broadcast_receiver(&args.multicast_ips, &interfaces, port).unwrap();

    log::debug!("Done Initializing\n");

    if !args.debugging && args.fork_to_background {
        // SAFETY: We are not using any shared memory and the parent exits right away upon success.
        if unsafe { libc::fork() != 0 } {
            std::process::exit(0)
        } else {
            /*
            TODO: Safe to do in Rust or could it cause `std` to crash later?
            fclose(stdin);
            fclose(stdout);
            fclose(stderr);
            */
        }
    }

    let mut control_buffer = [MaybeUninit::uninit(); CONTROL_BUFFER_SIZE];
    let mut packet_buffer = GRAM_BUFFER;

    loop {
        let Some(broadcast_packet) = receive_broadcast(
            &listener,
            &interfaces,
            ttl,
            port,
            &mut packet_buffer,
            control_buffer.as_mut_slice(),
        ) else {
            continue;
        };

        forward_packet(
            &interfaces,
            from_spoof_mode,
            dest_spoof_mode,
            port,
            ttl,
            &mut packet_buffer,
            &broadcast_packet,
        );
    }
}

struct ReceivedPacketInfo<'a> {
    originally_from: SocketAddrV4,
    originally_to_address: Ipv4Addr,
    size_received: usize,
    from_interface: &'a MachineIterface,
}

fn receive_broadcast<'a>(
    listener: &Socket,
    interfaces: &'a [MachineIterface],
    ttl: u8,
    port: u16,
    packet_buffer: &mut [u8; GRAM_BUFFER_SIZE],
    control_buffer: &mut [MaybeUninit<u8>],
) -> Option<ReceivedPacketInfo<'a>> {
    // SAFETY: The structure has no invariants.
    let mut rcv_addr: libc::sockaddr_in = unsafe { mem::zeroed() };

    let packet_buffer = &mut packet_buffer[HEADER_LEN as usize..];
    let mut iov = libc::iovec {
        iov_base: packet_buffer.as_mut_ptr().cast(),
        iov_len: packet_buffer.len() - 1,
    };

    let control_len = control_buffer.len() as _;
    let mut received_msg_header = {
        let mut header: MaybeUninit<msghdr> = MaybeUninit::zeroed();
        // SAFETY: A zeroed `msghdr` is a valid representation.
        let raw = unsafe { header.assume_init_mut() };

        raw.msg_namelen = size_of_val(&rcv_addr) as u32;
        raw.msg_name = (&raw mut rcv_addr).cast();
        raw.msg_iov = &mut iov;
        raw.msg_iovlen = 1;
        raw.msg_control = control_buffer.as_mut_ptr().cast();
        raw.msg_controllen = control_len;
        // SAFETY: All fields are either correctly set to 0 or filled with the correct field value.
        unsafe { header.assume_init() }
    };

    // SAFETY:
    // - The socket is a valid fd
    // - `received_msg_header` is valid to write and contains valid pointer buffers.
    let len = unsafe { libc::recvmsg(listener.as_raw_fd(), &mut received_msg_header, 0) };
    if len <= 0 {
        log::error!("recvmsg failed");
        return None;
    }

    let len = len as usize;

    let originally_from = SocketAddrV4::new(ip_from_raw(rcv_addr.sin_addr), rcv_addr.sin_port);

    if received_msg_header.msg_controllen == 0 {
        log::error!("no control msgs");
        return None;
    }

    // SAFETY:
    // - Returns a mutable pointer from `control_buffer`, which is a subset of the previous entire mutable borrow. Therefore it has not created multiple or overlapping &mut to the same data.
    // - `msghdr` is a valid control message buffer after `recvmsg` succeeded.
    let first_header = unsafe { NonNull::new(libc::CMSG_FIRSTHDR(&raw mut received_msg_header)) };

    let mut current_header = first_header;
    let other_headers = core::iter::from_fn(move || {
        let in_header = current_header?;
        // The borrow needs to stay inside this iterator producer so that `rcv_msg` can't be borrowed again
        // until after all the control messages have been viewed and the memory is no longer being referenced
        // by header pointers.
        // SAFETY:
        // - `mhdr` is a valid pointer that came from a message header function.
        // - `cmsg` is a valid pointer that came from a messager header function.
        current_header = unsafe {
            NonNull::new(libc::CMSG_NXTHDR(
                &raw mut received_msg_header,
                in_header.as_ptr(),
            ))
        };
        current_header
    });

    let all_headers = current_header
        .into_iter()
        .chain(other_headers)
        .map(|header_ptr| {
            // SAFETY: All header pointers came from valid control message
            // data and getter functions.
            unsafe { header_ptr.as_ref() }
        });

    let mut receive_ttl = None;
    let mut received_interface_index = None;
    let mut received_in_addr: Option<Ipv4Addr> = None;

    for cmsg in all_headers {
        #[cfg(any(target_os = "freebsd", target_os = "macos"))]
        {
            // "The pointer returned cannot be assumed to be suitably aligned for accessing arbitrary payload data types.
            // Applications should not cast it to a pointer type matching the payload...""
            if cmsg.cmsg_type == libc::IP_RECVTTL {
                // SAFETY:
                // - The buffer type was checked to match TTL data.
                // - The memory is read via a copy with no assumptions.
                receive_ttl = Some(unsafe { libc::CMSG_DATA(cmsg).cast::<i32>().read_unaligned() });
            }

            if cmsg.cmsg_type == libc::IP_RECVDSTADDR {
                // SAFETY:
                // - The buffer type was checked to match received IP data.
                // - The memory is read via a copy with no assumptions.
                let raw = unsafe {
                    libc::CMSG_DATA(cmsg)
                        .cast::<libc::in_addr>()
                        .read_unaligned()
                };
                received_in_addr = Some(ip_from_raw(raw));
            }

            if cmsg.cmsg_type == libc::IP_RECVIF {
                // SAFETY:
                // - The buffer type was checked to match receiving interface data.
                // - The memory is read via a copy with no assumptions.
                let interface_info = unsafe {
                    libc::CMSG_DATA(cmsg)
                        .cast::<libc::sockaddr_dl>()
                        .read_unaligned()
                };
                received_interface_index = Some(i32::from(interface_info.sdl_index));
            }
        }
        #[cfg(target_os = "linux")]
        {
            if cmsg.cmsg_type == libc::IP_TTL {
                // SAFETY:
                // - The buffer type was checked to match TTL data.
                // - The memory is read via a copy with no assumptions.
                receive_ttl = Some(unsafe { libc::CMSG_DATA(cmsg).cast::<i32>().read_unaligned() });
            }

            if cmsg.cmsg_type == libc::IP_PKTINFO {
                // SAFETY:
                // - The buffer type was checked to match received packet data.
                // - The memory is read via a copy with no assumptions.
                let packet_info = unsafe {
                    libc::CMSG_DATA(cmsg)
                        .cast::<libc::in_pktinfo>()
                        .read_unaligned()
                };

                received_interface_index = Some(packet_info.ipi_ifindex);
                received_in_addr = Some(ip_from_raw(packet_info.ipi_addr));
            }
        }
    }

    let Some(received_ttl) = receive_ttl.map(|ttl| ttl as u8) else {
        log::error!("TTL not found on incoming packet");
        return None;
    };

    let Some(received_interface_index) = received_interface_index else {
        log::error!("Interface not found on incoming packet");
        return None;
    };

    let Some(originally_to_address) = received_in_addr else {
        log::error!("Source IP not found on incoming packet");
        return None;
    };

    let originally_to_port = port;

    let from_interface = interfaces
        .iter()
        .find(|iface| iface.ifindex == received_interface_index);

    packet_buffer[HEADER_LEN as usize + len] = 0;

    log::debug!("<- [ {originally_from} -> {originally_to_address}:{originally_to_port} (iface={received_interface_index} len={len} ttl={received_ttl})");

    if received_ttl == ttl {
        log::debug!("Echo (Ignored)\n");
        return None;
    }

    let Some(from_interface) = from_interface else {
        log::debug!("Not from managed iface\n");
        return None;
    };

    Some(ReceivedPacketInfo {
        originally_from,
        originally_to_address,
        size_received: len,
        from_interface,
    })
}

fn forward_packet(
    interfaces: &[MachineIterface],
    from_spoof_mode: Option<SpoofFromAddrMode>,
    dest_spoof_mode: Option<SpoofDestAddrMode>,
    port: u16,
    ttl: u8,
    packet_buffer: &mut [u8; GRAM_BUFFER_SIZE],
    packet_info: &ReceivedPacketInfo,
) {
    // Iterate through our interfaces and send packet to each one
    for interface in interfaces
        .iter()
        // no bounces, please
        .filter(|iface| {
            // Difference from upstream:
            // Sending back on the same interface is allowed if the user has specified a custom
            // target IP that isn't broadcast (no storms, please).
            let same_interface = iface == &packet_info.from_interface;
            match dest_spoof_mode {
                Some(SpoofDestAddrMode::Other(dest)) => {
                    !dest.is_broadcast() && !dest.is_multicast()
                }
                Some(SpoofDestAddrMode::NewInterfaceBroadcast) | None => !same_interface,
            }
        })
    {
        let from_address = match from_spoof_mode {
            Some(SpoofFromAddrMode::BroadcastPort) => {
                SocketAddrV4::new(interface.interface_addr, port)
            }
            Some(SpoofFromAddrMode::SourcePort) => {
                SocketAddrV4::new(interface.interface_addr, packet_info.originally_from.port())
            }
            Some(SpoofFromAddrMode::Other(source)) => {
                SocketAddrV4::new(source, packet_info.originally_from.port())
            }
            None => packet_info.originally_from,
        };

        let to_address = match dest_spoof_mode {
            // user instructed us to override the target IP address
            Some(SpoofDestAddrMode::NewInterfaceBroadcast) => {
                // rewrite to new interface broadcast addr if user specified 255.255.255.255
                interface.destination_addr
            }
            Some(SpoofDestAddrMode::Other(target)) => {
                // else rewrite to specified value
                target
            }
            None if packet_info.originally_to_address == Ipv4Addr::BROADCAST
                || packet_info.originally_to_address
                    == packet_info.from_interface.destination_addr =>
            {
                // Received on interface broadcast address -- rewrite to new interface broadcast addr
                interface.destination_addr
            }
            None => {
                // Send to whatever IP it was originally to
                packet_info.originally_to_address
            }
        };

        let originally_to_port = port;
        let to_port = originally_to_port;

        log::debug!(
            "-> [ {from_address} -> {to_address}:{to_port} (iface={})",
            interface.ifindex
        );

        let len = packet_info.size_received;

        // Send the packet
        let packet_space = &mut packet_buffer[..26];

        packet_space[8] = ttl;

        packet_space[12..16].copy_from_slice(&from_address.ip().to_bits().to_be_bytes());
        packet_space[16..20].copy_from_slice(&to_address.to_bits().to_be_bytes());

        packet_space[20..22].copy_from_slice(&from_address.port().to_be_bytes());
        packet_space[22..24].copy_from_slice(&to_port.to_be_bytes());

        packet_space[24..26].copy_from_slice(&(UDPHEADER_LEN + len as u16).to_be_bytes());

        // Different from upstream: FreeBSD <= 10 support has been dropped because they are long out of support.
        let new_header_len = HEADER_LEN + len as u16;
        let new_header_len = if cfg!(target_os = "macos") {
            new_header_len.to_ne_bytes()
        } else {
            new_header_len.to_be_bytes()
        };

        packet_space[2..4].copy_from_slice(&new_header_len);

        let send_address = SockAddr::from(SocketAddrV4::new(to_address, to_port.to_be()));
        let to_send = &packet_buffer[..usize::from(HEADER_LEN) + len];

        if interface.socket.send_to(to_send, &send_address).is_err() {
            log::error!("sendto failed")
        }
    }

    log::debug!("");
}

fn discover_local_interfaces(
    requested_interfaces: &[ValidatedInterfaceName],
    ttl: u8,
) -> Result<Vec<MachineIterface>, anyhow::Error> {
    // Different from upstream: Use `SOCK_DGRAM` instead of `SOCK_RAW`.
    // This behaves better on some Linux kernels and matches the behavior of `ifconfig`.
    // Note that `ip addr` uses `PF_NETLINK` these days to obtain values.
    let discovery_proto = if cfg!(target_os = "linux") {
        Some(socket2::Protocol::from(libc::IPPROTO_IP))
    } else {
        None
    };
    let discovery_socket =
        Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, discovery_proto)
            .context("failed to discover sockets?")?;

    let mut interfaces = Vec::with_capacity(2);

    for interface in requested_interfaces {
        // Request index for this interface
        // Different from upstream: Skipped `ioctl` and used newer function everywhere instead.
        // SAFETY: `interface` contains a valid NUL-terminated string.
        let index = unsafe { libc::if_nametoindex(interface.0.as_ptr().cast()) };
        if index == 0 {
            return Err(anyhow::anyhow!(io::Error::last_os_error())
                .context("failed to convert interface name to index"));
        }

        let basereq = libc::ifreq {
            ifr_name: interface.0.map(|v| v as core::ffi::c_char),
            // SAFETY: The structure has no invariants.
            ifr_ifru: unsafe { mem::zeroed() },
        };

        // Request flags for this interface
        let inteface_flags = {
            let mut req = basereq;

            #[cfg(target_os = "linux")]
            nix::ioctl_read_bad!(read_interface_flags, SIOCGIFFLAGS, libc::ifreq);
            #[cfg(not(target_os = "linux"))]
            nix::ioctl_readwrite!(read_interface_flags, IOCTL_GROUP, SIOCGIFFLAGS, libc::ifreq);
            // SAFETY:
            // - The socket is valid.
            // - The ioctl is defined correctly.
            // - `data` is the right type and size.
            unsafe {
                read_interface_flags(discovery_socket.as_raw_fd(), &mut req)
                    .context("failed to read interface flags")?;
                i32::from(req.ifr_ifru.ifru_flags)
            }
        };

        // if the interface is not up or a loopback, ignore it
        if (inteface_flags & libc::IFF_UP == 0) || (inteface_flags & libc::IFF_LOOPBACK != 0) {
            continue;
        }

        let read_socket_addr_from_data = |data: libc::sockaddr| {
            // SAFETY: These types are identically sized, we are just reading it as a sub-type.
            let raw = unsafe { mem::transmute::<libc::sockaddr, libc::sockaddr_in>(data).sin_addr };
            ip_from_raw(raw)
        };

        // Get local IP for interface
        let interface_ip = {
            let mut req = basereq;

            #[cfg(target_os = "linux")]
            nix::ioctl_read_bad!(read_interface_ip, SIOCGIFADDR, libc::ifreq);
            #[cfg(not(target_os = "linux"))]
            nix::ioctl_readwrite!(read_interface_ip, IOCTL_GROUP, SIOCGIFADDR, libc::ifreq);
            // SAFETY:
            // - The socket is valid.
            // - The ioctl is defined correctly.
            // - `data` is the right type and size.
            unsafe {
                read_interface_ip(discovery_socket.as_raw_fd(), &mut req)
                    .context("failed to read interface IP")?;
                read_socket_addr_from_data(req.ifr_ifru.ifru_broadaddr)
            }
        };

        // Get broadcast address for interface
        let broadcast_ip = {
            let mut req = basereq;

            #[cfg(target_os = "linux")]
            nix::ioctl_read_bad!(read_interface_destination_addr, SIOCGIFDSTADDR, libc::ifreq);
            #[cfg(target_os = "linux")]
            nix::ioctl_read_bad!(read_interface_broadcast_addr, SIOCGIFBRDADDR, libc::ifreq);

            #[cfg(not(target_os = "linux"))]
            nix::ioctl_readwrite!(
                read_interface_destination_addr,
                IOCTL_GROUP,
                SIOCGIFDSTADDR,
                libc::ifreq
            );
            #[cfg(not(target_os = "linux"))]
            nix::ioctl_readwrite!(
                read_interface_broadcast_addr,
                IOCTL_GROUP,
                SIOCGIFBRDADDR,
                libc::ifreq
            );

            if (inteface_flags & libc::IFF_BROADCAST) != 0 {
                // SAFETY:
                // - The socket is valid.
                // - The ioctl is defined correctly.
                // - `data` is the right type and size.
                unsafe {
                    read_interface_broadcast_addr(discovery_socket.as_raw_fd(), &mut req)
                        .context("failed to read interface broadcast address")?;
                    read_socket_addr_from_data(req.ifr_ifru.ifru_broadaddr)
                }
            } else {
                // SAFETY:
                // - The socket is valid.
                // - The ioctl is defined correctly.
                // - `data` is the right type and size.
                unsafe {
                    read_interface_destination_addr(discovery_socket.as_raw_fd(), &mut req)
                        .context("failed to read interface destination address")?;
                    read_socket_addr_from_data(req.ifr_ifru.ifru_broadaddr)
                }
            }
        };

        log::debug!(
            "{}: {index} / {interface_ip} / {broadcast_ip}",
            interface.as_str()
        );

        // Set up a one raw socket per interface for sending our packets through
        let interface_socket = Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
        )
        .inspect_err(|_| {
            log::error!("failed to open broadcast socket, do you have appropiate permissions?");
        })?;

        interface_socket
            .set_broadcast(true)
            .context("failed setsockopt SO_BROADCAST")?;
        interface_socket
            .set_header_included(true)
            .context("failed setsockopt IP_HDRINCL")?;
        interface_socket
            .set_reuse_port(true)
            .context("failed setsockopt SO_REUSEPORT")?;

        #[cfg(any(target_os = "freebsd", target_os = "macos"))]
        {
            if let Err(e) = interface_socket.set_multicast_loop_v4(false) {
                log::error!("failed setsockopt IP_MULTICAST_LOOP: {e}");
            }

            if let Err(e) = interface_socket.set_multicast_if_v4(&interface_ip) {
                log::error!("failed setsockopt IP_MULTICAST_IF: {e}");
            }

            if let Err(e) = interface_socket.set_multicast_ttl_v4(u32::from(ttl)) {
                log::error!("failed setsockopt IP_MULTICAST_TTL: {e}");
            }
        }
        #[cfg(target_os = "linux")]
        {
            let _ = ttl;
            // bind socket to dedicated NIC (override routing table)
            interface_socket
                .bind_device(Some(interface.as_str().as_bytes()))
                .context("failed setsockopt SO_BINDTODEVICE")?;
        }

        interfaces.push(MachineIterface {
            destination_addr: broadcast_ip,
            interface_addr: interface_ip,
            ifindex: index as i32,
            socket: interface_socket,
        })
    }

    log::debug!("found {} interfaces total", interfaces.len());

    Ok(interfaces)
}

fn setup_broadcast_receiver(
    multicast_addresses: &[Ipv4Addr],
    interfaces: &[MachineIterface],
    listen_port: u16,
) -> Result<Socket, anyhow::Error> {
    let listener = Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("failed to create listener")?;

    listener
        .set_broadcast(true)
        .context("failed setsockopt SO_BROADCAST")?;

    listener
        .set_reuse_port(true)
        .context("failed setsockopt SO_REUSEPORT")?;

    // XXX: No Rust bindings for any of the IP_RECV parts needed yet :(
    // This is what they demand our respect for D:
    let enable_sockopt = |name: i32| -> std::io::Result<()> {
        static TRUE_VAL: i32 = true as u8 as i32;
        #[cfg(any(target_os = "freebsd", target_os = "macos"))]
        const LEVEL: i32 = libc::IPPROTO_IP;
        #[cfg(target_os = "linux")]
        const LEVEL: i32 = libc::SOL_IP;

        // SAFETY:
        // - The socket is valid.
        // - Only known constants are used for `level` and `name`,
        // - `value` is the correct type to toggle a boolean option.
        // - `option_len` is always the correct size.
        let ret = unsafe {
            libc::setsockopt(
                listener.as_raw_fd(),
                LEVEL,
                name,
                (&raw const TRUE_VAL).cast(),
                size_of::<i32>() as u32,
            )
        };

        match ret {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    };

    #[cfg(any(target_os = "freebsd", target_os = "macos"))]
    {
        enable_sockopt(libc::IP_RECVTTL).context("failed to set IP_RECVTTL on listener")?;
        enable_sockopt(libc::IP_RECVIF).context("failed to set IP_RECVIF on listener")?;
        enable_sockopt(libc::IP_RECVDSTADDR).context("failed to set IP_RECVDSTADDR on listener")?;
    }

    #[cfg(target_os = "linux")]
    {
        enable_sockopt(libc::IP_RECVTTL).context("failed to set IP_RECVTTL on listener")?;
        enable_sockopt(libc::IP_PKTINFO).context("failed to set IP_PKTINFO on listener")?;
    }

    for multi_addr in multicast_addresses {
        for interface in interfaces {
            let interface_addr = interface.interface_addr;

            log::debug!("IP_ADDR_MEMBERSHIP: \t\t{interface_addr} {multi_addr}");

            listener
                .join_multicast_v4(multi_addr, &interface_addr)
                .context("failed to set IP_ADD_MEMBERSHIP on listener")?;
        }
    }

    let bind_addr = SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, listen_port));
    listener
        .bind(&bind_addr)
        .context("failed to bind listener")?;

    Ok(listener)
}
