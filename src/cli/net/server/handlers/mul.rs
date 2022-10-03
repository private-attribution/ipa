use crate::cli::net::server::MpcServerError;
use crate::cli::net::{BufferedMessages, RecordHeaders};
use crate::protocol::{QueryId, Step};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{self, FromRequest, RequestParts};
use tokio::sync::mpsc;

pub struct Path<S: Step>(QueryId, S);
#[async_trait]
impl<B: Send, S: Step> FromRequest<B> for Path<S> {
    type Rejection = MpcServerError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let extract::Path((query_id, step)) =
            extract::Path::<(QueryId, String)>::from_request(req).await?;
        let step = S::try_from(step).map_err::<serde_json::Error, _>(serde::de::Error::custom)?;
        Ok(Path(query_id, step))
    }
}

/// accepts all the relevant information from the request, and push all of it onto the `outgoing`
/// channel
/// TODO: implement the receiving end of `outgoing`
pub async fn handler<S: Step>(
    outgoing: mpsc::Sender<BufferedMessages<S>>,
    Path(query_id, step): Path<S>,
    RecordHeaders { offset, data_size }: RecordHeaders,
    body: Bytes,
) -> Result<(), MpcServerError> {
    outgoing
        .send(BufferedMessages {
            query_id,
            step,
            offset,
            data_size,
            body,
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::net::mpc_helper_router;
    use crate::protocol::IPAProtocolStep;
    use axum::http::{Request, StatusCode};
    use axum_server::service::SendService;
    use hyper::{body, Body};
    use tower::ServiceExt;

    fn build_req<S: Step>(
        query_id: QueryId,
        step: S,
        offset: usize,
        data_size: usize,
        body: &'static [u8],
    ) -> Request<Body> {
        assert_eq!(
            body.len() % data_size,
            0,
            "body len must align with data_size"
        );
        let uri = format!(
            "http://localhost:3000/mul/query-id/{}/step/{}",
            query_id, step
        );
        let headers = RecordHeaders { offset, data_size };
        let body = Body::from(Bytes::from_static(body));
        headers
            .add_to(Request::post(uri))
            .body(body)
            .expect("request should be valid")
    }

    #[tokio::test]
    async fn collect_req() {
        const DATA_SIZE: usize = 4;
        let query_id = QueryId;
        let step = IPAProtocolStep::ConvertShares;
        let offset = 0;
        let body = &[0; DATA_SIZE * 3];

        let req = build_req(query_id, step, offset, DATA_SIZE, body);
        let (tx, mut rx) = mpsc::channel(1);
        let service = mpc_helper_router::<IPAProtocolStep>(tx).into_service();
        let resp = service.oneshot(req).await.unwrap();
        let status = resp.status();
        let resp_body = body::to_bytes(resp.into_body()).await.unwrap();
        let resp_body_str = String::from_utf8_lossy(&resp_body);

        assert_eq!(status, StatusCode::OK, "{}", resp_body_str);
        let messages = rx.try_recv().expect("should have already received value");
        assert_eq!(
            messages,
            BufferedMessages {
                query_id,
                step,
                offset,
                data_size: DATA_SIZE,
                body: Bytes::from_static(body),
            }
        );
    }
}
