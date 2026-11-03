//! Per-connection order, request-ID and total checks, applied to frames the decoder
//! already bounded (design 5.2, 5.3). A connection carries one `Hello` exchange, then
//! exactly one operation:
//!
//! - control: one `Initialize`, `Probe` or `Cancel`, and its `Ready`, `ProbeReply` or
//!   `CancelAck` (or an `Error`);
//! - exec: `Exec` (request ID = execution token), `Accepted` (or an `Error`), the
//!   declared stdin and one `StdinEnd`; after the command settles, contiguous
//!   `Stdout` frames, then contiguous `Stderr` frames, then one `Result` (or an
//!   `Error`), then a clean EOF.
//!
//! Anything else (an unsolicited or repeated reply, a foreign request ID, output after
//! the terminal frame, a second terminal frame, stdin over- or undershoot, totals that
//! disagree with the `Result`) is a typed [`ProtocolError`].

use crate::error::{ProtocolError, Result};
use crate::frame::Frame;
use crate::header::Kind;
use crate::message::{Channel, ErrorReply, ExecResult, Hello, HelloReply, Message};
use crate::types::{Hex32, Id128};

fn unexpected(kind: Kind, state: &'static str) -> ProtocolError {
    ProtocolError::UnexpectedKind { kind, state }
}

fn terminal(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Ready | Kind::ProbeReply | Kind::CancelAck | Kind::Result | Kind::Error
    )
}

/// What the host learned from one frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostEvent {
    HelloReply(Box<HelloReply>),
    /// The control reply: `Ready`, `ProbeReply` or `CancelAck`.
    Reply(Message),
    Accepted,
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Result(Box<ExecResult>),
    /// A typed refusal or failure; terminal. Never success or absence.
    Error(ErrorReply),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostState {
    AwaitHelloReply,
    /// The `HelloReply` arrived; nothing is due until the host sends its request.
    Identified,
    AwaitReply(Kind),
    AwaitAccepted,
    /// Waiting for the command to settle, then output in order.
    Output {
        stderr_started: bool,
    },
    Done,
}

/// The host's view of one connection.
#[derive(Debug)]
pub struct HostConnection {
    channel: Channel,
    hello_id: Id128,
    challenge: Hex32,
    state: HostState,
    request_id: Option<Id128>,
    max_output: u64,
    stdout: u64,
    stderr: u64,
    stdin_declared: u64,
    stdin_sent: u64,
    stdin_ended: bool,
    cancel_token: Option<Id128>,
}

impl HostConnection {
    /// After sending `hello` under `hello_id`.
    pub fn new(hello_id: Id128, hello: &Hello) -> Self {
        Self {
            channel: hello.channel,
            hello_id,
            challenge: hello.challenge,
            state: HostState::AwaitHelloReply,
            request_id: None,
            max_output: 0,
            stdout: 0,
            stderr: 0,
            stdin_declared: 0,
            stdin_sent: 0,
            stdin_ended: false,
            cancel_token: None,
        }
    }

    pub fn done(&self) -> bool {
        self.state == HostState::Done
    }

    /// Records a frame the host is about to send, refusing one out of order, so host
    /// code cannot send a request before identification, a second request, stdin
    /// beyond its declaration or anything after `StdinEnd`.
    pub fn sending(&mut self, request_id: Id128, message: &Message) -> Result<()> {
        let kind = message.kind();
        match (self.channel, self.state, message) {
            (Channel::Control, HostState::Identified, Message::Initialize(_)) => {
                self.state = HostState::AwaitReply(Kind::Ready);
            }
            (Channel::Control, HostState::Identified, Message::Probe(_)) => {
                self.state = HostState::AwaitReply(Kind::ProbeReply);
            }
            (Channel::Control, HostState::Identified, Message::Cancel(cancel)) => {
                self.cancel_token = Some(cancel.token);
                self.state = HostState::AwaitReply(Kind::CancelAck);
            }
            (Channel::Exec, HostState::Identified, Message::Exec(exec)) => {
                if exec.token != request_id {
                    return Err(ProtocolError::RequestId);
                }
                self.max_output = exec.max_output;
                self.stdin_declared = exec.stdin_bytes;
                self.state = HostState::AwaitAccepted;
            }
            _ => return Err(unexpected(kind, "for the host to send now")),
        }
        self.request_id = Some(request_id);
        Ok(())
    }

    /// Records stdin the host is about to send after `Accepted`.
    pub fn sending_stdin(&mut self, request_id: Id128, message: &Message) -> Result<()> {
        if self.state
            != (HostState::Output {
                stderr_started: false,
            })
            || self.stdout != 0
            || self.stdin_ended
            || Some(request_id) != self.request_id
        {
            return Err(unexpected(message.kind(), "for stdin now"));
        }
        match message {
            Message::Stdin(bytes) => {
                if bytes.is_empty() {
                    return Err(ProtocolError::EmptyData);
                }
                let sent = self.stdin_sent + bytes.len() as u64;
                if sent > self.stdin_declared {
                    return Err(ProtocolError::StdinLength {
                        declared: self.stdin_declared,
                        got: sent,
                    });
                }
                self.stdin_sent = sent;
            }
            Message::StdinEnd(end) => {
                if Some(end.token) != self.request_id
                    || end.total != self.stdin_declared
                    || self.stdin_sent != self.stdin_declared
                {
                    return Err(ProtocolError::StdinLength {
                        declared: self.stdin_declared,
                        got: self.stdin_sent,
                    });
                }
                self.stdin_ended = true;
            }
            other => return Err(unexpected(other.kind(), "for stdin now")),
        }
        Ok(())
    }

    /// Checks one received frame.
    pub fn received(&mut self, frame: Frame) -> Result<HostEvent> {
        let kind = frame.kind();
        let id = frame.request_id();
        match self.state {
            HostState::Done => {
                return Err(if terminal(kind) {
                    ProtocolError::DuplicateTerminal
                } else {
                    ProtocolError::TrailingBytes
                });
            }
            HostState::AwaitHelloReply => {
                if id != self.hello_id {
                    return Err(ProtocolError::RequestId);
                }
                return match frame.into_message()? {
                    Message::HelloReply(reply) => {
                        if reply.challenge != self.challenge {
                            return Err(ProtocolError::InvalidField("challenge echo"));
                        }
                        self.state = HostState::Identified;
                        Ok(HostEvent::HelloReply(reply))
                    }
                    Message::Error(error) => {
                        self.state = HostState::Done;
                        Ok(HostEvent::Error(error))
                    }
                    other => Err(unexpected(other.kind(), "before HelloReply")),
                };
            }
            HostState::Identified => {
                return Err(unexpected(kind, "before the host's request"));
            }
            _ => {}
        }
        if Some(id) != self.request_id {
            return Err(ProtocolError::RequestId);
        }
        let token = self.request_id.expect("set with the request");
        let message = frame.into_message()?;
        match (self.state, message) {
            (HostState::AwaitReply(expected), message) if message.kind() == expected => {
                if let Message::CancelAck(ack) = &message
                    && Some(ack.token) != self.cancel_token
                {
                    return Err(ProtocolError::InvalidField("cancel token"));
                }
                self.state = HostState::Done;
                Ok(HostEvent::Reply(message))
            }
            // The command starts only after all stdin, so no output can precede it.
            (HostState::Output { .. }, message)
                if !self.stdin_ended && !matches!(message, Message::Error(_)) =>
            {
                Err(unexpected(message.kind(), "before StdinEnd"))
            }
            (HostState::AwaitAccepted, Message::Accepted(accepted)) => {
                if accepted.token != token {
                    return Err(ProtocolError::InvalidField("accepted token"));
                }
                self.state = HostState::Output {
                    stderr_started: false,
                };
                Ok(HostEvent::Accepted)
            }
            (
                HostState::Output {
                    stderr_started: false,
                },
                Message::Stdout(bytes),
            ) => {
                self.stdout += bytes.len() as u64;
                if self.stdout > self.max_output {
                    return Err(ProtocolError::CaptureMismatch);
                }
                Ok(HostEvent::Stdout(bytes))
            }
            (HostState::Output { .. }, Message::Stderr(bytes)) => {
                self.state = HostState::Output {
                    stderr_started: true,
                };
                self.stderr += bytes.len() as u64;
                if self.stderr > self.max_output {
                    return Err(ProtocolError::CaptureMismatch);
                }
                Ok(HostEvent::Stderr(bytes))
            }
            (HostState::Output { .. }, Message::Result(result)) => {
                if result.token != token {
                    return Err(ProtocolError::InvalidField("result token"));
                }
                if result.stdout.kept != self.stdout || result.stderr.kept != self.stderr {
                    return Err(ProtocolError::CaptureMismatch);
                }
                self.state = HostState::Done;
                Ok(HostEvent::Result(result))
            }
            (HostState::AwaitReply(_) | HostState::AwaitAccepted, Message::Error(error))
            | (HostState::Output { .. }, Message::Error(error)) => {
                self.state = HostState::Done;
                Ok(HostEvent::Error(error))
            }
            (HostState::Output { .. }, message) => Err(unexpected(
                message.kind(),
                "in output order (Stdout, then Stderr, then Result)",
            )),
            (_, message) => Err(unexpected(message.kind(), "as the reply to this request")),
        }
    }

    /// A clean EOF is valid only after the terminal frame.
    pub fn eof(&self) -> Result<()> {
        if self.done() {
            Ok(())
        } else {
            Err(ProtocolError::EofBeforeTerminal)
        }
    }
}

/// What the broker learned from one frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestEvent {
    Hello(Hello),
    /// The control request: `Initialize`, `Probe` or `Cancel`.
    Request(Message),
    Exec(crate::message::Exec),
    Stdin(Vec<u8>),
    /// Exactly the declared stdin arrived.
    StdinEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuestState {
    AwaitHello,
    AwaitRequest(Channel),
    Stdin,
    Done,
}

/// The broker's view of one connection.
#[derive(Debug)]
pub struct GuestConnection {
    state: GuestState,
    hello_id: Option<Id128>,
    request_id: Option<Id128>,
    declared: u64,
    received: u64,
}

impl Default for GuestConnection {
    fn default() -> Self {
        Self {
            state: GuestState::AwaitHello,
            hello_id: None,
            request_id: None,
            declared: 0,
            received: 0,
        }
    }
}

impl GuestConnection {
    pub fn hello_id(&self) -> Option<Id128> {
        self.hello_id
    }

    pub fn request_id(&self) -> Option<Id128> {
        self.request_id
    }

    pub fn done(&self) -> bool {
        self.state == GuestState::Done
    }

    pub fn received(&mut self, frame: Frame) -> Result<GuestEvent> {
        let kind = frame.kind();
        let id = frame.request_id();
        match self.state {
            GuestState::Done => Err(ProtocolError::TrailingBytes),
            GuestState::AwaitHello => match frame.into_message()? {
                Message::Hello(hello) => {
                    self.hello_id = Some(id);
                    self.state = GuestState::AwaitRequest(hello.channel);
                    Ok(GuestEvent::Hello(hello))
                }
                other => Err(unexpected(other.kind(), "before Hello")),
            },
            GuestState::AwaitRequest(Channel::Control) => match kind {
                Kind::Initialize | Kind::Probe | Kind::Cancel => {
                    let message = frame.into_message()?;
                    self.request_id = Some(id);
                    self.state = GuestState::Done;
                    Ok(GuestEvent::Request(message))
                }
                _ => Err(unexpected(kind, "on a control channel")),
            },
            GuestState::AwaitRequest(Channel::Exec) => match frame.into_message()? {
                Message::Exec(exec) => {
                    if exec.token != id {
                        return Err(ProtocolError::RequestId);
                    }
                    self.request_id = Some(id);
                    self.declared = exec.stdin_bytes;
                    self.state = GuestState::Stdin;
                    Ok(GuestEvent::Exec(exec))
                }
                other => Err(unexpected(other.kind(), "on an exec channel before Exec")),
            },
            GuestState::Stdin => {
                if Some(id) != self.request_id {
                    return Err(ProtocolError::RequestId);
                }
                match frame.into_message()? {
                    Message::Stdin(bytes) => {
                        if bytes.is_empty() {
                            return Err(ProtocolError::EmptyData);
                        }
                        let received = self.received + bytes.len() as u64;
                        if received > self.declared {
                            return Err(ProtocolError::StdinLength {
                                declared: self.declared,
                                got: received,
                            });
                        }
                        self.received = received;
                        Ok(GuestEvent::Stdin(bytes))
                    }
                    Message::StdinEnd(end) => {
                        if Some(end.token) != self.request_id {
                            return Err(ProtocolError::InvalidField("stdin end token"));
                        }
                        if end.total != self.declared || self.received != self.declared {
                            return Err(ProtocolError::StdinLength {
                                declared: self.declared,
                                got: self.received,
                            });
                        }
                        self.state = GuestState::Done;
                        Ok(GuestEvent::StdinEnd)
                    }
                    other => Err(unexpected(other.kind(), "during stdin")),
                }
            }
        }
    }

    /// The host may close its write half only after its last frame.
    pub fn eof(&self) -> Result<()> {
        if self.done() {
            Ok(())
        } else {
            Err(ProtocolError::EofBeforeTerminal)
        }
    }
}
