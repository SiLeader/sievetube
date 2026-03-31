/// Wire protocol for communication between Edge and Connector over QUIC.
///
/// # Frame format
/// ```text
/// [4 bytes: payload length (big-endian u32)] [1 byte: message tag] [N bytes: JSON payload]
/// ```
///
/// # Handshake flow
/// 1. Connector opens a unidirectional QUIC stream and sends AuthRequest.
/// 2. Edge replies on a unidirectional stream with AuthResponse.
/// 3. For each inbound connection, Edge opens a bidirectional QUIC stream,
///    sends ConnectRequest, then the stream becomes a raw byte pipe.
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::Protocol;
use crate::error::SieveTubeError;

pub const ALPN_PROTOCOL: &[u8] = b"sievetube/1";
pub const MAX_FRAME_SIZE: u32 = 64 * 1024; // 64 KiB for control frames

// Message type tags
const TAG_AUTH_REQUEST: u8 = 0x01;
const TAG_AUTH_RESPONSE: u8 = 0x02;
const TAG_CONNECT_REQUEST: u8 = 0x03;

/// Sent by Connector → Edge to authenticate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub jwt: String,
}

/// Sent by Edge → Connector in response to AuthRequest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub ok: bool,
    pub reason: Option<String>,
}

/// Sent by Edge → Connector at the start of each new bidirectional stream.
/// After this frame, the stream is a raw byte pipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub request_id: u64,
    pub hostname: String,
    pub protocol: Protocol,
    pub client_addr: SocketAddr,
}

pub enum Message {
    AuthRequest(AuthRequest),
    AuthResponse(AuthResponse),
    ConnectRequest(ConnectRequest),
}

pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Message,
) -> Result<(), SieveTubeError> {
    let (tag, payload) = match msg {
        Message::AuthRequest(m) => (TAG_AUTH_REQUEST, serde_json::to_vec(m).unwrap()),
        Message::AuthResponse(m) => (TAG_AUTH_RESPONSE, serde_json::to_vec(m).unwrap()),
        Message::ConnectRequest(m) => (TAG_CONNECT_REQUEST, serde_json::to_vec(m).unwrap()),
    };

    let total_len = 1 + payload.len(); // tag byte + payload
    if total_len > MAX_FRAME_SIZE as usize {
        return Err(SieveTubeError::Protocol("frame too large".to_string()));
    }

    writer.write_u32(total_len as u32).await?;
    writer.write_u8(tag).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Message, SieveTubeError> {
    let len = reader.read_u32().await?;
    if len > MAX_FRAME_SIZE {
        return Err(SieveTubeError::Protocol(format!(
            "frame too large: {len} bytes"
        )));
    }
    if len < 1 {
        return Err(SieveTubeError::Protocol("empty frame".to_string()));
    }

    let tag = reader.read_u8().await?;
    let payload_len = (len - 1) as usize;
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;

    let msg = match tag {
        TAG_AUTH_REQUEST => {
            let m: AuthRequest = serde_json::from_slice(&payload)
                .map_err(|e| SieveTubeError::Protocol(e.to_string()))?;
            Message::AuthRequest(m)
        }
        TAG_AUTH_RESPONSE => {
            let m: AuthResponse = serde_json::from_slice(&payload)
                .map_err(|e| SieveTubeError::Protocol(e.to_string()))?;
            Message::AuthResponse(m)
        }
        TAG_CONNECT_REQUEST => {
            let m: ConnectRequest = serde_json::from_slice(&payload)
                .map_err(|e| SieveTubeError::Protocol(e.to_string()))?;
            Message::ConnectRequest(m)
        }
        _ => {
            return Err(SieveTubeError::Protocol(format!(
                "unknown message tag: 0x{tag:02x}"
            )))
        }
    };

    Ok(msg)
}

/// Header prefixed to each QUIC datagram for UDP forwarding.
/// Format: [8 bytes: request_id] [2 bytes: hostname_len] [hostname_len bytes: hostname] [payload]
pub struct DatagramHeader {
    pub request_id: u64,
    pub hostname: String,
}

impl DatagramHeader {
    pub fn encode(&self, payload: &[u8]) -> bytes::Bytes {
        let hostname_bytes = self.hostname.as_bytes();
        let mut buf = bytes::BytesMut::with_capacity(
            8 + 2 + hostname_bytes.len() + payload.len(),
        );
        buf.extend_from_slice(&self.request_id.to_be_bytes());
        buf.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(hostname_bytes);
        buf.extend_from_slice(payload);
        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 10 {
            return None;
        }
        let request_id = u64::from_be_bytes(data[0..8].try_into().ok()?);
        let hostname_len = u16::from_be_bytes(data[8..10].try_into().ok()?) as usize;
        if data.len() < 10 + hostname_len {
            return None;
        }
        let hostname = std::str::from_utf8(&data[10..10 + hostname_len]).ok()?.to_string();
        let payload = &data[10 + hostname_len..];
        Some((DatagramHeader { request_id, hostname }, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn round_trip_auth_request() {
        let mut buf = Vec::new();
        let msg = Message::AuthRequest(AuthRequest {
            jwt: "test.jwt.token".to_string(),
        });
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_message(&mut cursor).await.unwrap();
        assert!(matches!(decoded, Message::AuthRequest(_)));
    }

    #[tokio::test]
    async fn round_trip_auth_response() {
        let mut buf = Vec::new();
        let msg = Message::AuthResponse(AuthResponse {
            ok: true,
            reason: None,
        });
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_message(&mut cursor).await.unwrap();
        assert!(matches!(decoded, Message::AuthResponse(AuthResponse { ok: true, .. })));
    }

    #[tokio::test]
    async fn round_trip_connect_request() {
        let mut buf = Vec::new();
        let msg = Message::ConnectRequest(ConnectRequest {
            request_id: 42,
            hostname: "web.example.com".to_string(),
            protocol: Protocol::Http,
            client_addr: "192.168.1.1:12345".parse().unwrap(),
        });
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_message(&mut cursor).await.unwrap();
        assert!(matches!(decoded, Message::ConnectRequest(ConnectRequest { request_id: 42, .. })));
    }

    #[test]
    fn datagram_header_round_trip() {
        let header = DatagramHeader {
            request_id: 99,
            hostname: "game.example.com".to_string(),
        };
        let payload = b"hello udp";
        let encoded = header.encode(payload);
        let (decoded, decoded_payload) = DatagramHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.request_id, 99);
        assert_eq!(decoded.hostname, "game.example.com");
        assert_eq!(decoded_payload, payload);
    }
}
