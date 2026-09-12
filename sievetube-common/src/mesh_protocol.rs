//! Edge-to-Edge forwarding protocol (`sievetube-mesh/1`).
//!
//! Independent of the Connector protocol: it uses its own ALPN, requires mutual
//! TLS between Edges and has its own messages. An ingress Edge opens a
//! bidirectional stream, sends a [`ForwardRequest`] and waits for a
//! [`ForwardResponse`]; after acceptance the stream is a raw byte pipe to the
//! Connector attached to the receiving Edge.
//!
//! # Frame format
//! ```text
//! [4 bytes: length (big-endian u32)] [1 byte: tag] [N bytes: JSON]
//! ```

use std::net::SocketAddr;

use bytes::{BufMut, Bytes, BytesMut};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::Protocol;
use crate::error::SieveTubeError;
use crate::hostname;

pub const MESH_ALPN: &[u8] = b"sievetube-mesh/1";
pub const MESH_VERSION: u16 = 1;
/// Maximum control frame size; forwarding metadata is small.
pub const MAX_MESH_FRAME: u32 = 8 * 1024;
/// Maximum length of identifiers carried in mesh messages.
pub const MAX_ID_LEN: usize = 256;

const TAG_FORWARD_REQUEST: u8 = 0x10;
const TAG_FORWARD_RESPONSE: u8 = 0x11;

/// Sent by the ingress Edge on a new bidirectional stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardRequest {
    pub version: u16,
    /// Must equal the authenticated peer identity
    pub ingress_edge_id: String,
    pub tenant_id: String,
    pub hostname: String,
    pub protocol: Protocol,
    /// Client address observed by the ingress Edge (trusted as peer metadata)
    pub client_addr: SocketAddr,
    pub request_id: u64,
    /// Remaining forwarding hops; the receiver only delivers locally
    pub hops_remaining: u8,
    /// Connector registration generation the route was advertised for
    pub connection_generation: u64,
}

impl ForwardRequest {
    /// Structural checks every receiver performs before authorization.
    pub fn validate(&self) -> Result<(), RejectReason> {
        if self.version != MESH_VERSION {
            return Err(RejectReason::UnsupportedVersion);
        }
        if self.hops_remaining == 0 {
            return Err(RejectReason::HopLimit);
        }
        let ids_ok = [&self.ingress_edge_id, &self.tenant_id, &self.hostname]
            .iter()
            .all(|id| !id.is_empty() && id.len() <= MAX_ID_LEN);
        let hostname_ok =
            hostname::normalize_hostname(&self.hostname).is_ok_and(|h| h == self.hostname);
        if !ids_ok || !hostname_ok {
            return Err(RejectReason::Invalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    UnsupportedVersion,
    HopLimit,
    NotAuthorized,
    NoRoute,
    Overloaded,
    Invalid,
}

impl RejectReason {
    /// Whether another candidate Edge may be tried. Nothing was forwarded yet.
    pub fn retryable(self) -> bool {
        matches!(self, RejectReason::NoRoute | RejectReason::Overloaded)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::UnsupportedVersion => "unsupported_version",
            RejectReason::HopLimit => "hop_limit",
            RejectReason::NotAuthorized => "not_authorized",
            RejectReason::NoRoute => "no_route",
            RejectReason::Overloaded => "overloaded",
            RejectReason::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardResponse {
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject: Option<RejectReason>,
}

impl ForwardResponse {
    pub fn accept() -> Self {
        ForwardResponse {
            accepted: true,
            reject: None,
        }
    }

    pub fn reject(reason: RejectReason) -> Self {
        ForwardResponse {
            accepted: false,
            reject: Some(reason),
        }
    }
}

async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    tag: u8,
    message: &T,
) -> Result<(), SieveTubeError> {
    let payload =
        serde_json::to_vec(message).map_err(|e| SieveTubeError::Protocol(e.to_string()))?;
    let len = payload.len() + 1;
    if len > MAX_MESH_FRAME as usize {
        return Err(SieveTubeError::Protocol("mesh frame too large".to_string()));
    }
    writer.write_u32(len as u32).await?;
    writer.write_u8(tag).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
    expected_tag: u8,
) -> Result<T, SieveTubeError> {
    let len = reader.read_u32().await?;
    if len == 0 || len > MAX_MESH_FRAME {
        return Err(SieveTubeError::Protocol(format!(
            "invalid mesh frame length {len}"
        )));
    }
    let tag = reader.read_u8().await?;
    if tag != expected_tag {
        return Err(SieveTubeError::Protocol(format!(
            "unexpected mesh frame tag 0x{tag:02x}"
        )));
    }
    let mut payload = vec![0u8; len as usize - 1];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).map_err(|e| SieveTubeError::Protocol(e.to_string()))
}

pub async fn write_forward_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request: &ForwardRequest,
) -> Result<(), SieveTubeError> {
    write_frame(writer, TAG_FORWARD_REQUEST, request).await
}

pub async fn read_forward_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ForwardRequest, SieveTubeError> {
    read_frame(reader, TAG_FORWARD_REQUEST).await
}

pub async fn write_forward_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &ForwardResponse,
) -> Result<(), SieveTubeError> {
    write_frame(writer, TAG_FORWARD_RESPONSE, response).await
}

pub async fn read_forward_response<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ForwardResponse, SieveTubeError> {
    read_frame(reader, TAG_FORWARD_RESPONSE).await
}

const DATAGRAM_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshDatagramKind {
    Request = 1,
    Reply = 2,
}

/// Header of a UDP payload forwarded between Edges. Replies are matched on the
/// ingress Edge by `request_id`, and carry `ingress_edge_id` so that a reply can
/// never be delivered through a different ingress.
///
/// ```text
/// [1: version][1: kind][8: request_id][8: connection_generation]
/// [2: len][ingress_edge_id][2: len][tenant_id][2: len][hostname][payload]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshDatagramHeader {
    pub kind: MeshDatagramKind,
    pub request_id: u64,
    pub connection_generation: u64,
    pub ingress_edge_id: String,
    pub tenant_id: String,
    pub hostname: String,
}

impl MeshDatagramHeader {
    pub fn encoded_len(&self) -> usize {
        1 + 1 + 8 + 8 + 6 + self.ingress_edge_id.len() + self.tenant_id.len() + self.hostname.len()
    }

    /// Encode the header followed by `payload`.
    ///
    /// A field longer than [`MAX_ID_LEN`] is an error rather than truncated: a
    /// shortened hostname or tenant id would address something else on the
    /// receiving side, and cutting inside a multi-byte character would make the
    /// datagram undecodable.
    pub fn encode(&self, payload: &[u8]) -> Result<Bytes, SieveTubeError> {
        for (what, field) in [
            ("ingress_edge_id", &self.ingress_edge_id),
            ("tenant_id", &self.tenant_id),
            ("hostname", &self.hostname),
        ] {
            if field.len() > MAX_ID_LEN {
                return Err(SieveTubeError::Protocol(format!(
                    "mesh datagram {what} of {} bytes exceeds {MAX_ID_LEN}",
                    field.len()
                )));
            }
        }
        let mut buf = BytesMut::with_capacity(self.encoded_len() + payload.len());
        buf.put_u8(DATAGRAM_VERSION);
        buf.put_u8(self.kind as u8);
        buf.put_u64(self.request_id);
        buf.put_u64(self.connection_generation);
        for field in [&self.ingress_edge_id, &self.tenant_id, &self.hostname] {
            let bytes = field.as_bytes();
            buf.put_u16(bytes.len() as u16);
            buf.put_slice(bytes);
        }
        buf.put_slice(payload);
        Ok(buf.freeze())
    }

    pub fn decode(data: &[u8]) -> Result<(Self, &[u8]), SieveTubeError> {
        let invalid =
            |what: &str| SieveTubeError::Protocol(format!("invalid mesh datagram: {what}"));
        if data.len() < 18 {
            return Err(invalid("truncated header"));
        }
        if data[0] != DATAGRAM_VERSION {
            return Err(invalid("unsupported version"));
        }
        let kind = match data[1] {
            1 => MeshDatagramKind::Request,
            2 => MeshDatagramKind::Reply,
            _ => return Err(invalid("unknown kind")),
        };
        let request_id = u64::from_be_bytes(data[2..10].try_into().expect("8 bytes"));
        let connection_generation = u64::from_be_bytes(data[10..18].try_into().expect("8 bytes"));
        let mut rest = &data[18..];
        let mut fields = Vec::with_capacity(3);
        for _ in 0..3 {
            if rest.len() < 2 {
                return Err(invalid("truncated field"));
            }
            let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if len > MAX_ID_LEN || rest.len() < 2 + len {
                return Err(invalid("field length"));
            }
            let value =
                std::str::from_utf8(&rest[2..2 + len]).map_err(|_| invalid("field encoding"))?;
            fields.push(value.to_string());
            rest = &rest[2 + len..];
        }
        let hostname = fields.pop().expect("three fields");
        let tenant_id = fields.pop().expect("three fields");
        let ingress_edge_id = fields.pop().expect("three fields");
        Ok((
            MeshDatagramHeader {
                kind,
                request_id,
                connection_generation,
                ingress_edge_id,
                tenant_id,
                hostname,
            },
            rest,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn request() -> ForwardRequest {
        ForwardRequest {
            version: MESH_VERSION,
            ingress_edge_id: "edge-a".into(),
            tenant_id: "tenant-1".into(),
            hostname: "web.example.com".into(),
            protocol: Protocol::Http,
            client_addr: "203.0.113.5:40000".parse().unwrap(),
            request_id: 7,
            hops_remaining: 1,
            connection_generation: 3,
        }
    }

    #[tokio::test]
    async fn forward_messages_round_trip() {
        let mut buf = Vec::new();
        write_forward_request(&mut buf, &request()).await.unwrap();
        write_forward_response(&mut buf, &ForwardResponse::reject(RejectReason::NoRoute))
            .await
            .unwrap();
        let mut cursor = Cursor::new(buf);
        assert_eq!(read_forward_request(&mut cursor).await.unwrap(), request());
        let response = read_forward_response(&mut cursor).await.unwrap();
        assert_eq!(response.reject, Some(RejectReason::NoRoute));
        assert!(RejectReason::NoRoute.retryable());
        assert!(!RejectReason::NotAuthorized.retryable());
    }

    #[tokio::test]
    async fn rejects_oversized_and_mistagged_frames() {
        let mut oversized = Vec::new();
        oversized.extend_from_slice(&(MAX_MESH_FRAME + 1).to_be_bytes());
        oversized.push(TAG_FORWARD_REQUEST);
        assert!(read_forward_request(&mut Cursor::new(oversized))
            .await
            .is_err());

        let mut buf = Vec::new();
        write_forward_response(&mut buf, &ForwardResponse::accept())
            .await
            .unwrap();
        assert!(read_forward_request(&mut Cursor::new(buf)).await.is_err());

        // The Connector protocol's AuthRequest tag is not a mesh message.
        let mut connector_frame = Vec::new();
        crate::protocol::write_message(
            &mut connector_frame,
            &crate::protocol::Message::AuthRequest(crate::protocol::AuthRequest {
                jwt: "x".into(),
                services: None,
            }),
        )
        .await
        .unwrap();
        assert!(read_forward_request(&mut Cursor::new(connector_frame))
            .await
            .is_err());

        let mut huge = request();
        huge.tenant_id = "t".repeat(MAX_MESH_FRAME as usize);
        assert!(write_forward_request(&mut Vec::new(), &huge).await.is_err());
    }

    #[test]
    fn validation() {
        assert_eq!(request().validate(), Ok(()));
        let mut r = request();
        r.version = 2;
        assert_eq!(r.validate(), Err(RejectReason::UnsupportedVersion));
        let mut r = request();
        r.hops_remaining = 0;
        assert_eq!(r.validate(), Err(RejectReason::HopLimit));
        let mut r = request();
        r.hostname = "Web.Example.com".into();
        assert_eq!(r.validate(), Err(RejectReason::Invalid));
        let mut r = request();
        r.tenant_id = String::new();
        assert_eq!(r.validate(), Err(RejectReason::Invalid));
    }

    #[test]
    fn datagram_header_round_trip_and_rejects_garbage() {
        let header = MeshDatagramHeader {
            kind: MeshDatagramKind::Reply,
            request_id: 99,
            connection_generation: 4,
            ingress_edge_id: "edge-a".into(),
            tenant_id: "tenant".into(),
            hostname: "game.example.com".into(),
        };
        let encoded = header.encode(b"payload").unwrap();
        assert_eq!(encoded.len(), header.encoded_len() + 7);
        let (decoded, payload) = MeshDatagramHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(payload, b"payload");

        assert!(MeshDatagramHeader::decode(&encoded[..10]).is_err());
        let mut wrong_version = encoded.to_vec();
        wrong_version[0] = 9;
        assert!(MeshDatagramHeader::decode(&wrong_version).is_err());
        let mut bad_length = encoded.to_vec();
        bad_length[18] = 0xff;
        assert!(MeshDatagramHeader::decode(&bad_length).is_err());
    }

    #[test]
    fn encode_rejects_overlong_fields_instead_of_truncating() {
        let mut header = MeshDatagramHeader {
            kind: MeshDatagramKind::Request,
            request_id: 1,
            connection_generation: 1,
            ingress_edge_id: "edge-a".into(),
            tenant_id: "tenant".into(),
            hostname: "game.example.com".into(),
        };
        // A truncated hostname would resolve to a different registration.
        header.hostname = format!("{}.test", "h".repeat(MAX_ID_LEN));
        assert!(header.encode(b"payload").is_err());
        // Truncation must not be able to split a multi-byte character either.
        header.hostname = "game.example.com".into();
        header.tenant_id = "\u{3066}".repeat(MAX_ID_LEN);
        assert!(header.encode(b"payload").is_err());
    }
}
