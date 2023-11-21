// Smoldot
// Copyright (C) 2023  Pierre Krieger
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use smoldot::libp2p::multiaddr::{Multiaddr, Protocol};

use super::{Address, ConnectionType, IpAddr, MultiStreamAddress};
use core::str;

pub enum AddressOrMultiStreamAddress<'a> {
    Address(Address<'a>),
    MultiStreamAddress(MultiStreamAddress),
}

impl<'a> From<&'a AddressOrMultiStreamAddress<'a>> for ConnectionType {
    fn from(address: &'a AddressOrMultiStreamAddress<'a>) -> ConnectionType {
        match address {
            AddressOrMultiStreamAddress::Address(a) => ConnectionType::from(a),
            AddressOrMultiStreamAddress::MultiStreamAddress(a) => ConnectionType::from(a),
        }
    }
}

/// Parses a [`Multiaddr`] into an [`Address`] or [`MultiStreamAddress`].
pub fn multiaddr_to_address(multiaddr: &Multiaddr) -> Result<AddressOrMultiStreamAddress, Error> {
    let mut iter = multiaddr.iter().fuse();

    let proto1 = iter.next().ok_or(Error::UnknownCombination)?;
    let proto2 = iter.next().ok_or(Error::UnknownCombination)?;
    let proto3 = iter.next();
    let proto4 = iter.next();

    if iter.next().is_some() {
        return Err(Error::UnknownCombination);
    }

    Ok(match (proto1, proto2, proto3, proto4) {
        (Protocol::Ip4(ip), Protocol::Tcp(port), None, None) => {
            AddressOrMultiStreamAddress::Address(Address::TcpIp {
                ip: IpAddr::V4(ip),
                port,
            })
        }
        (Protocol::Ip6(ip), Protocol::Tcp(port), None, None) => {
            AddressOrMultiStreamAddress::Address(Address::TcpIp {
                ip: IpAddr::V6(ip),
                port,
            })
        }
        (
            Protocol::Dns(addr) | Protocol::Dns4(addr) | Protocol::Dns6(addr),
            Protocol::Tcp(port),
            None,
            None,
        ) => AddressOrMultiStreamAddress::Address(Address::TcpDns {
            hostname: str::from_utf8(addr.into_bytes()).map_err(Error::NonUtf8DomainName)?,
            port,
        }),
        (Protocol::Ip4(ip), Protocol::Tcp(port), Some(Protocol::Ws), None) => {
            AddressOrMultiStreamAddress::Address(Address::WebSocketIp {
                ip: IpAddr::V4(ip),
                port,
            })
        }
        (Protocol::Ip6(ip), Protocol::Tcp(port), Some(Protocol::Ws), None) => {
            AddressOrMultiStreamAddress::Address(Address::WebSocketIp {
                ip: IpAddr::V6(ip),
                port,
            })
        }
        (
            Protocol::Dns(addr) | Protocol::Dns4(addr) | Protocol::Dns6(addr),
            Protocol::Tcp(port),
            Some(Protocol::Ws),
            None,
        ) => AddressOrMultiStreamAddress::Address(Address::WebSocketDns {
            hostname: str::from_utf8(addr.into_bytes()).map_err(Error::NonUtf8DomainName)?,
            port,
            secure: false,
        }),
        (
            Protocol::Dns(addr) | Protocol::Dns4(addr) | Protocol::Dns6(addr),
            Protocol::Tcp(port),
            Some(Protocol::Wss),
            None,
        )
        | (
            Protocol::Dns(addr) | Protocol::Dns4(addr) | Protocol::Dns6(addr),
            Protocol::Tcp(port),
            Some(Protocol::Tls),
            Some(Protocol::Ws),
        ) => AddressOrMultiStreamAddress::Address(Address::WebSocketDns {
            hostname: str::from_utf8(addr.into_bytes()).map_err(Error::NonUtf8DomainName)?,
            port,
            secure: true,
        }),

        (
            Protocol::Ip4(ip),
            Protocol::Udp(port),
            Some(Protocol::WebRtcDirect),
            Some(Protocol::Certhash(multihash)),
        ) => {
            if multihash.hash_algorithm_code() != 0x12 {
                return Err(Error::NonSha256Certhash);
            }
            let Ok(&remote_certificate_sha256) = <&[u8; 32]>::try_from(multihash.data()) else {
                return Err(Error::InvalidMultihashLength);
            };
            AddressOrMultiStreamAddress::MultiStreamAddress(MultiStreamAddress::WebRtc {
                ip: IpAddr::V4(ip),
                port,
                remote_certificate_sha256,
            })
        }

        (
            Protocol::Ip6(ip),
            Protocol::Udp(port),
            Some(Protocol::WebRtcDirect),
            Some(Protocol::Certhash(multihash)),
        ) => {
            if multihash.hash_algorithm_code() != 0x12 {
                return Err(Error::NonSha256Certhash);
            }
            let Ok(&remote_certificate_sha256) = <&[u8; 32]>::try_from(multihash.data()) else {
                return Err(Error::InvalidMultihashLength);
            };
            AddressOrMultiStreamAddress::MultiStreamAddress(MultiStreamAddress::WebRtc {
                ip: IpAddr::V6(ip),
                port,
                remote_certificate_sha256,
            })
        }

        _ => return Err(Error::UnknownCombination),
    })
}

#[derive(Debug, Clone, derive_more::Display)]
pub enum Error {
    /// Unknown combination of protocols.
    UnknownCombination,

    /// Multiaddress contains a domain name that isn't UTF-8.
    ///
    /// > **Note**: According to RFC2181 section 11, a domain name is not necessarily an UTF-8
    /// >           string. Any binary data can be used as a domain name, provided it follows
    /// >           a few restrictions (notably its length). However, in this context, we
    /// >           automatically consider as non-supported a multiaddress that contains a
    /// >           non-UTF-8 domain name, for the sake of simplicity.
    NonUtf8DomainName(str::Utf8Error),

    /// Multiaddr contains a `/certhash` components whose multihash isn't using SHA-256, but the
    /// rest of the multiaddr requires SHA-256.
    NonSha256Certhash,

    /// Multiaddr contains a multihash whose length doesn't match its hash algorithm.
    InvalidMultihashLength,
}
