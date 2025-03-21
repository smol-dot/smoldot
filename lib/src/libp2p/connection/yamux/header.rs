// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
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

//! Decodes Yamux headers.
//!
//! See <https://github.com/hashicorp/yamux/blob/master/spec.md>

use core::num::NonZero;

/// A Yamux header in its decoded form.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DecodedYamuxHeader {
    Data {
        /// Value of the SYN flag.
        syn: bool,
        /// Value of the ACK flag.
        ack: bool,
        /// Value of the FIN flag.
        fin: bool,
        /// Value of the RST flag.
        rst: bool,
        stream_id: NonZero<u32>,
        length: u32,
    },
    Window {
        /// Value of the SYN flag.
        syn: bool,
        /// Value of the ACK flag.
        ack: bool,
        /// Value of the FIN flag.
        fin: bool,
        /// Value of the RST flag.
        rst: bool,
        stream_id: NonZero<u32>,
        length: u32,
    },
    PingRequest {
        opaque_value: u32,
    },
    PingResponse {
        opaque_value: u32,
    },
    GoAway {
        error_code: GoAwayErrorCode,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum GoAwayErrorCode {
    NormalTermination = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
}

/// Encodes a Yamux header.
pub fn encode(header: &DecodedYamuxHeader) -> [u8; 12] {
    match header {
        DecodedYamuxHeader::Data {
            syn,
            ack,
            fin,
            rst,
            stream_id,
            length,
        }
        | DecodedYamuxHeader::Window {
            syn,
            ack,
            fin,
            rst,
            stream_id,
            length,
        } => {
            let ty = match header {
                DecodedYamuxHeader::Data { .. } => 0,
                DecodedYamuxHeader::Window { .. } => 1,
                _ => unreachable!(),
            };

            let mut flags: u8 = 0;
            if *syn {
                flags |= 0x1;
            }
            if *ack {
                flags |= 0x2;
            }
            if *fin {
                flags |= 0x4;
            }
            if *rst {
                flags |= 0x8;
            }

            let stream_id = stream_id.get().to_be_bytes();
            let length = length.to_be_bytes();

            [
                0,
                ty,
                0,
                flags,
                stream_id[0],
                stream_id[1],
                stream_id[2],
                stream_id[3],
                length[0],
                length[1],
                length[2],
                length[3],
            ]
        }
        DecodedYamuxHeader::PingRequest { opaque_value }
        | DecodedYamuxHeader::PingResponse { opaque_value } => {
            let flags = match header {
                DecodedYamuxHeader::PingRequest { .. } => 1,
                DecodedYamuxHeader::PingResponse { .. } => 2,
                _ => unreachable!(),
            };

            let opaque_value = opaque_value.to_be_bytes();

            [
                0,
                2,
                0,
                flags,
                0,
                0,
                0,
                0,
                opaque_value[0],
                opaque_value[1],
                opaque_value[2],
                opaque_value[3],
            ]
        }
        DecodedYamuxHeader::GoAway { error_code } => {
            let code = match error_code {
                GoAwayErrorCode::NormalTermination => 0,
                GoAwayErrorCode::ProtocolError => 1,
                GoAwayErrorCode::InternalError => 2,
            };

            [0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, code]
        }
    }
}

/// Decodes a Yamux header.
pub fn decode_yamux_header(bytes: &[u8; 12]) -> Result<DecodedYamuxHeader, YamuxHeaderDecodeError> {
    match nom::Parser::parse(
        &mut nom::combinator::all_consuming(nom::combinator::complete(decode)),
        bytes,
    ) {
        Ok((_, h)) => Ok(h),
        Err(nom::Err::Incomplete(_)) => unreachable!(),
        Err(nom::Err::Failure(err) | nom::Err::Error(err)) => Err(YamuxHeaderDecodeError {
            offset: err.input.as_ptr() as usize - bytes.as_ptr() as usize,
        }),
    }
}

/// Error while decoding a Yamux header.
#[derive(Debug, derive_more::Display, derive_more::Error)]
#[display("Error at offset {offset}")]
pub struct YamuxHeaderDecodeError {
    offset: usize,
}

fn decode(bytes: &[u8]) -> nom::IResult<&[u8], DecodedYamuxHeader> {
    nom::Parser::parse(
        &mut nom::sequence::preceded(
            nom::bytes::streaming::tag(&[0][..]),
            nom::branch::alt((
                nom::combinator::map(
                    (
                        nom::bytes::streaming::tag(&[0][..]),
                        flags,
                        nom::combinator::map_opt(
                            nom::number::streaming::be_u32,
                            NonZero::<u32>::new,
                        ),
                        nom::number::streaming::be_u32,
                    ),
                    |(_, (syn, ack, fin, rst), stream_id, length)| DecodedYamuxHeader::Data {
                        syn,
                        ack,
                        fin,
                        rst,
                        stream_id,
                        length,
                    },
                ),
                nom::combinator::map(
                    (
                        nom::bytes::streaming::tag(&[1][..]),
                        flags,
                        nom::combinator::map_opt(
                            nom::number::streaming::be_u32,
                            NonZero::<u32>::new,
                        ),
                        nom::number::streaming::be_u32,
                    ),
                    |(_, (syn, ack, fin, rst), stream_id, length)| DecodedYamuxHeader::Window {
                        syn,
                        ack,
                        fin,
                        rst,
                        stream_id,
                        length,
                    },
                ),
                nom::combinator::map(
                    (
                        nom::bytes::streaming::tag(&[2][..]),
                        nom::bytes::streaming::tag(&[0x0, 0x1][..]),
                        nom::bytes::streaming::tag(&[0, 0, 0, 0][..]),
                        nom::number::streaming::be_u32,
                    ),
                    |(_, _, _, opaque_value)| DecodedYamuxHeader::PingRequest { opaque_value },
                ),
                nom::combinator::map(
                    (
                        nom::bytes::streaming::tag(&[2][..]),
                        nom::bytes::streaming::tag(&[0x0, 0x2][..]),
                        nom::bytes::streaming::tag(&[0, 0, 0, 0][..]),
                        nom::number::streaming::be_u32,
                    ),
                    |(_, _, _, opaque_value)| DecodedYamuxHeader::PingResponse { opaque_value },
                ),
                nom::combinator::map(
                    (
                        nom::bytes::streaming::tag(&[3][..]),
                        nom::bytes::streaming::tag(&[0, 0][..]),
                        nom::bytes::streaming::tag(&[0, 0, 0, 0][..]),
                        nom::branch::alt((
                            nom::combinator::map(
                                nom::bytes::streaming::tag(&0u32.to_be_bytes()[..]),
                                |_| GoAwayErrorCode::NormalTermination,
                            ),
                            nom::combinator::map(
                                nom::bytes::streaming::tag(&1u32.to_be_bytes()[..]),
                                |_| GoAwayErrorCode::ProtocolError,
                            ),
                            nom::combinator::map(
                                nom::bytes::streaming::tag(&2u32.to_be_bytes()[..]),
                                |_| GoAwayErrorCode::InternalError,
                            ),
                        )),
                    ),
                    |(_, _, _, error_code)| DecodedYamuxHeader::GoAway { error_code },
                ),
            )),
        ),
        bytes,
    )
}

fn flags(bytes: &[u8]) -> nom::IResult<&[u8], (bool, bool, bool, bool)> {
    nom::Parser::parse(
        &mut nom::combinator::map_opt(nom::number::streaming::be_u16, |flags| {
            let syn = (flags & 0x1) != 0;
            let ack = (flags & 0x2) != 0;
            let fin = (flags & 0x4) != 0;
            let rst = (flags & 0x8) != 0;
            if (flags & !0b1111) != 0 {
                return None;
            }
            Some((syn, ack, fin, rst))
        }),
        bytes,
    )
}

#[cfg(test)]
mod tests {
    use core::num::NonZero;

    #[test]
    fn decode_data_frame() {
        assert_eq!(
            super::decode_yamux_header(&[0, 0, 0, 1, 0, 0, 0, 15, 0, 0, 2, 65]).unwrap(),
            super::DecodedYamuxHeader::Data {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
                stream_id: NonZero::<u32>::new(15).unwrap(),
                length: 577
            }
        );
    }

    #[test]
    fn decode_ping_frame() {
        assert_eq!(
            super::decode_yamux_header(&[0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 1, 12]).unwrap(),
            super::DecodedYamuxHeader::PingRequest { opaque_value: 268 }
        );

        assert_eq!(
            super::decode_yamux_header(&[0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 1, 12]).unwrap(),
            super::DecodedYamuxHeader::PingResponse { opaque_value: 268 }
        );

        assert!(super::decode_yamux_header(&[0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());

        assert!(super::decode_yamux_header(&[0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]).is_ok());
        assert!(super::decode_yamux_header(&[0, 2, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]).is_err());

        assert!(super::decode_yamux_header(&[0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).is_ok());
        assert!(super::decode_yamux_header(&[0, 2, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]).is_err());

        assert!(super::decode_yamux_header(&[0, 2, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0]).is_err());
        assert!(super::decode_yamux_header(&[0, 2, 0, 5, 0, 0, 0, 1, 0, 0, 0, 0]).is_err());
        assert!(super::decode_yamux_header(&[0, 2, 0, 9, 0, 0, 0, 1, 0, 0, 0, 0]).is_err());
        assert!(super::decode_yamux_header(&[0, 2, 0, 17, 0, 0, 0, 1, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn decode_goaway() {
        assert_eq!(
            super::decode_yamux_header(&[0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            super::DecodedYamuxHeader::GoAway {
                error_code: super::GoAwayErrorCode::NormalTermination,
            }
        );

        assert_eq!(
            super::decode_yamux_header(&[0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap(),
            super::DecodedYamuxHeader::GoAway {
                error_code: super::GoAwayErrorCode::ProtocolError,
            }
        );

        assert_eq!(
            super::decode_yamux_header(&[0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]).unwrap(),
            super::DecodedYamuxHeader::GoAway {
                error_code: super::GoAwayErrorCode::InternalError,
            }
        );

        assert!(super::decode_yamux_header(&[0, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(super::decode_yamux_header(&[0, 3, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(super::decode_yamux_header(&[0, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(super::decode_yamux_header(&[0, 3, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]).is_err());
        assert!(super::decode_yamux_header(&[0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(super::decode_yamux_header(&[0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]).is_err());
        assert!(super::decode_yamux_header(&[0, 3, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]).is_err());
    }

    #[test]
    fn version_check() {
        assert!(super::decode_yamux_header(&[0, 0, 0, 1, 0, 0, 0, 15, 0, 0, 2, 65]).is_ok());
        assert!(super::decode_yamux_header(&[2, 0, 0, 1, 0, 0, 0, 15, 0, 0, 2, 65]).is_err());
    }

    macro_rules! check_encode_redecodes {
        ($payload:expr) => {{
            let payload = $payload;
            assert_eq!(
                super::decode_yamux_header(&super::encode(&payload)).unwrap(),
                payload
            );
        }};
    }

    #[test]
    fn encode_data() {
        for _ in 0..500 {
            check_encode_redecodes!(super::DecodedYamuxHeader::Data {
                syn: rand::random(),
                ack: rand::random(),
                fin: rand::random(),
                rst: rand::random(),
                stream_id: rand::random(),
                length: rand::random()
            });
        }
    }

    #[test]
    fn encode_window() {
        for _ in 0..500 {
            check_encode_redecodes!(super::DecodedYamuxHeader::Window {
                syn: rand::random(),
                ack: rand::random(),
                fin: rand::random(),
                rst: rand::random(),
                stream_id: rand::random(),
                length: rand::random()
            });
        }
    }

    #[test]
    fn encode_ping() {
        check_encode_redecodes!(super::DecodedYamuxHeader::PingRequest {
            opaque_value: rand::random(),
        });

        check_encode_redecodes!(super::DecodedYamuxHeader::PingResponse {
            opaque_value: rand::random(),
        });
    }

    #[test]
    fn encode_goaway() {
        check_encode_redecodes!(super::DecodedYamuxHeader::GoAway {
            error_code: super::GoAwayErrorCode::NormalTermination,
        });

        check_encode_redecodes!(super::DecodedYamuxHeader::GoAway {
            error_code: super::GoAwayErrorCode::ProtocolError,
        });

        check_encode_redecodes!(super::DecodedYamuxHeader::GoAway {
            error_code: super::GoAwayErrorCode::InternalError,
        });
    }
}
