use std::{
    fmt,
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};
use thiserror::Error;

/// Error returned by bounded body operations.
#[derive(Debug, Error)]
pub enum BodyLimitError<E> {
    /// The body exceeded its configured decoded-byte limit.
    #[error("request body exceeds the {limit} byte limit (observed at least {observed} bytes)")]
    TooLarge { limit: usize, observed: usize },
    /// The underlying body failed while being read.
    #[error("request body read failed: {0}")]
    Upstream(E),
    /// A body yielded a frame that was neither data nor trailers.
    #[error("request body yielded an invalid frame")]
    InvalidFrame,
}

impl<E: PartialEq> PartialEq for BodyLimitError<E> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::TooLarge {
                    limit: left_limit,
                    observed: left_observed,
                },
                Self::TooLarge {
                    limit: right_limit,
                    observed: right_observed,
                },
            ) => left_limit == right_limit && left_observed == right_observed,
            (Self::Upstream(left), Self::Upstream(right)) => left == right,
            (Self::InvalidFrame, Self::InvalidFrame) => true,
            _ => false,
        }
    }
}

/// A streaming body wrapper that rejects data after the decoded byte limit is
/// crossed.  Trailers are passed through unchanged.
pub struct LimitedBody<B> {
    inner: Pin<Box<B>>,
    limit: usize,
    seen: usize,
    exceeded: bool,
}

impl<B> LimitedBody<B> {
    /// Wrap `inner`, counting only data frames against `limit`.
    #[must_use]
    pub fn new(inner: B, limit: usize) -> Self {
        Self {
            inner: Box::pin(inner),
            limit,
            seen: 0,
            exceeded: false,
        }
    }

    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }

    #[must_use]
    pub fn bytes_seen(&self) -> usize {
        self.seen
    }

    #[must_use]
    pub fn into_inner(self) -> Pin<Box<B>> {
        self.inner
    }
}

impl<B> fmt::Debug for LimitedBody<B>
where
    B: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LimitedBody")
            .field("inner", &self.inner)
            .field("limit", &self.limit)
            .field("seen", &self.seen)
            .field("exceeded", &self.exceeded)
            .finish()
    }
}

impl<B> Body for LimitedBody<B>
where
    B: Body,
    B::Data: Buf,
{
    type Data = B::Data;
    type Error = BodyLimitError<B::Error>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.exceeded {
            return Poll::Ready(Some(Err(BodyLimitError::TooLarge {
                limit: self.limit,
                observed: self.seen,
            })));
        }

        match self.inner.as_mut().poll_frame(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Some(Err(BodyLimitError::Upstream(error))))
            }
            Poll::Ready(Some(Ok(frame))) => {
                match frame.into_data() {
                    Ok(data) => {
                        let bytes = data.remaining();
                        let observed = self.seen.saturating_add(bytes);
                        if bytes > self.limit.saturating_sub(self.seen) {
                            self.seen = observed;
                            self.exceeded = true;
                            return Poll::Ready(Some(Err(BodyLimitError::TooLarge {
                                limit: self.limit,
                                observed,
                            })));
                        }
                        self.seen = observed;
                        // We consumed no bytes from the Buf; the frame still owns
                        // the original data and can be forwarded unchanged.
                        Poll::Ready(Some(Ok(Frame::data(data))))
                    }
                    Err(frame) => {
                        // `into_data` returns the original frame for trailers. A
                        // trailer does not contribute to the decoded-byte limit.
                        // Reconstructing via `into_trailers` retains it exactly.
                        // The frame can only be data or trailers by contract.
                        match frame.into_trailers() {
                            Ok(trailers) => Poll::Ready(Some(Ok(Frame::trailers(trailers)))),
                            Err(_) => Poll::Ready(Some(Err(BodyLimitError::InvalidFrame))),
                        }
                    }
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let inner = self.inner.size_hint();
        let remaining = self.limit.saturating_sub(self.seen) as u64;
        let mut hint = SizeHint::new();
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper.min(remaining));
        } else {
            hint.set_upper(remaining);
        }
        // The wrapper may fail before yielding any data when a single frame
        // crosses the limit, so it cannot safely retain the inner lower bound.
        hint
    }
}

/// A streaming body wrapper that rejects any single data frame larger than
/// `limit`. The aggregate byte count is enforced separately by
/// [`LimitedBody`]. Trailers pass through unchanged.
pub struct FrameLimitedBody<B> {
    inner: Pin<Box<B>>,
    limit: usize,
}

impl<B> FrameLimitedBody<B> {
    /// Wraps `inner` with a per-data-frame bound.
    #[must_use]
    pub fn new(inner: B, limit: usize) -> Self {
        Self {
            inner: Box::pin(inner),
            limit,
        }
    }

    /// Maximum bytes accepted in one data frame.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

impl<B> Body for FrameLimitedBody<B>
where
    B: Body,
    B::Data: Buf,
{
    type Data = B::Data;
    type Error = BodyLimitError<B::Error>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.inner.as_mut().poll_frame(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Some(Err(BodyLimitError::Upstream(error))))
            }
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let observed = data.remaining();
                    if observed > self.limit {
                        return Poll::Ready(Some(Err(BodyLimitError::TooLarge {
                            limit: self.limit,
                            observed,
                        })));
                    }
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(frame) => match frame.into_trailers() {
                    Ok(trailers) => Poll::Ready(Some(Ok(Frame::trailers(trailers)))),
                    Err(_) => Poll::Ready(Some(Err(BodyLimitError::InvalidFrame))),
                },
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Read a body into memory while enforcing a decoded-byte limit.
///
/// The limit is checked against a body's known lower size bound before
/// allocation and on every data frame.  An upper bound may overestimate the
/// body, so it is not used for early rejection.  Trailers are consumed and
/// discarded because the return type represents data bytes only.
pub async fn collect_body_limited<B>(
    body: B,
    limit: usize,
) -> Result<Bytes, BodyLimitError<B::Error>>
where
    B: Body,
    B::Data: Buf,
{
    let hint = body.size_hint();
    let lower = hint.lower();
    if lower > limit as u64 {
        return Err(BodyLimitError::TooLarge {
            limit,
            observed: lower.min(usize::MAX as u64) as usize,
        });
    }

    let mut body = Box::pin(body);
    let mut output = BytesMut::with_capacity(lower.min(limit as u64) as usize);
    while let Some(frame) = poll_fn(|context| body.as_mut().poll_frame(context)).await {
        let frame = frame.map_err(BodyLimitError::Upstream)?;
        match frame.into_data() {
            Ok(mut data) => {
                let chunk_len = data.remaining();
                let observed = output.len().saturating_add(chunk_len);
                if chunk_len > limit.saturating_sub(output.len()) {
                    return Err(BodyLimitError::TooLarge { limit, observed });
                }
                output.extend_from_slice(&data.copy_to_bytes(chunk_len));
            }
            Err(frame) => {
                if frame.into_trailers().is_err() {
                    return Err(BodyLimitError::InvalidFrame);
                }
            }
        }
    }

    Ok(output.freeze())
}

/// Name emphasizing that the helper reads the complete body.
pub async fn read_body_limited<B>(body: B, limit: usize) -> Result<Bytes, BodyLimitError<B::Error>>
where
    B: Body,
    B::Data: Buf,
{
    collect_body_limited(body, limit).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures_util::stream;
    use http::HeaderMap;
    use http_body::Frame;
    use http_body_util::{BodyExt, Full, StreamBody};
    use std::{
        convert::Infallible,
        pin::Pin,
        task::{Context, Poll},
    };

    #[derive(Debug)]
    struct HintedBody {
        data: Option<Bytes>,
        hint: SizeHint,
    }

    impl HintedBody {
        fn new(data: Option<Bytes>, lower: u64, upper: Option<u64>) -> Self {
            let mut hint = SizeHint::new();
            hint.set_lower(lower);
            if let Some(upper) = upper {
                hint.set_upper(upper);
            }
            Self { data, hint }
        }
    }

    impl Body for HintedBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.data.take().map(|data| Ok(Frame::data(data))))
        }

        fn size_hint(&self) -> SizeHint {
            self.hint
        }
    }

    #[tokio::test]
    async fn collects_body_at_limit_and_rejects_over_limit() {
        let body = Full::new(Bytes::from_static(b"hello"));
        assert_eq!(
            collect_body_limited(body, 5).await.unwrap(),
            Bytes::from_static(b"hello")
        );

        let body = Full::new(Bytes::from_static(b"hello!"));
        assert_eq!(
            collect_body_limited(body, 5).await,
            Err(BodyLimitError::TooLarge {
                limit: 5,
                observed: 6
            })
        );
    }

    #[tokio::test]
    async fn size_hint_only_rejects_when_lower_bound_exceeds_limit() {
        let body = HintedBody::new(Some(Bytes::from_static(b"ok")), 0, Some(10));
        assert_eq!(
            collect_body_limited(body, 2).await.unwrap(),
            Bytes::from_static(b"ok")
        );

        let body = HintedBody::new(None, 3, None);
        assert_eq!(
            collect_body_limited(body, 2).await,
            Err(BodyLimitError::TooLarge {
                limit: 2,
                observed: 3
            })
        );
    }

    #[tokio::test]
    async fn bounded_wrapper_preserves_trailers() {
        let frames = stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"abc"))),
            Ok(Frame::trailers({
                let mut trailers = HeaderMap::new();
                trailers.insert("x-checksum", "ok".try_into().unwrap());
                trailers
            })),
        ]);
        let body = StreamBody::new(frames);
        let mut bounded = LimitedBody::new(body, 3);
        let first = bounded.frame().await.unwrap().unwrap();
        assert_eq!(first.into_data().unwrap(), Bytes::from_static(b"abc"));
        let second = bounded.frame().await.unwrap().unwrap();
        assert!(second.into_trailers().is_ok());
        assert!(bounded.frame().await.is_none());
    }

    #[tokio::test]
    async fn bounded_wrapper_errors_on_second_chunk() {
        let frames = stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"ab"))),
            Ok(Frame::data(Bytes::from_static(b"cd"))),
        ]);
        let body = StreamBody::new(frames);
        let mut bounded = LimitedBody::new(body, 3);
        assert!(bounded.frame().await.unwrap().unwrap().is_data());
        let error = bounded.frame().await.unwrap().unwrap_err();
        assert_eq!(
            error,
            BodyLimitError::TooLarge {
                limit: 3,
                observed: 4
            }
        );
    }

    #[tokio::test]
    async fn frame_limited_wrapper_rejects_one_large_frame() {
        let frames = stream::iter([Ok::<_, Infallible>(Frame::data(Bytes::from_static(
            b"abcd",
        )))]);
        let body = StreamBody::new(frames);
        let mut bounded = FrameLimitedBody::new(body, 3);
        assert_eq!(
            bounded.frame().await.unwrap().unwrap_err(),
            BodyLimitError::TooLarge {
                limit: 3,
                observed: 4,
            }
        );
    }
}
