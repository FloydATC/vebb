
use std::io::BufReader;
use std::io::prelude::*;
use bytes::BytesMut;
use bytes::Buf;
use ascii::AsciiChar;
use std::net::{SocketAddr, TcpListener, TcpStream, Shutdown};

pub use http::{Request, Response, StatusCode, Method, HeaderName, HeaderValue, HeaderMap};
pub use bytes::Bytes;

type ReqBuilder = http::request::Builder;

const MAX_LINE_LENGTH: u64 = 32768;
const MAX_REQ_HEADER_COUNT: usize = 1024;


type ConnectionCallback = fn(TcpStream);


pub struct Server {
    listener: TcpListener,
    callback: ConnectionCallback,
}


impl Server {

    pub fn new(listener: TcpListener, connection_handler: ConnectionCallback) -> Self {
        Server {
            listener,
            callback: connection_handler,
        }
    }

    pub fn run(&mut self) -> Result<(), std::io::Error> {
        println!("server listening for incoming connections");
        loop {
            let (stream, _peer) = self.listener.accept()?;
            println!("listener returned something");
            (&self.callback)(stream);
        }
    }

}


type RequestCallback = fn(Request<Bytes>) -> Response<Bytes>;


pub struct Connection {
    stream: TcpStream,
    callback: RequestCallback,
}


impl Connection {

    pub fn new(stream: TcpStream, request_handler: RequestCallback) -> Self {
        Connection {
            stream,
            callback: request_handler,
        }
    }


    pub fn run(&mut self) -> Result<(), std::io::Error> {
        let mut reader = BufReader::new(self.stream.try_clone().unwrap());
        loop {
            // Read request from stream
            let opt_request = match read_request(&mut reader) {
                Ok(opt_request) => opt_request,
                Err(status) => {
                    // TODO: Generate error response
                    println!("run() read_request returned {}", status);
                    break;
                }
            };

            // Check if we received a request
            let request = match opt_request {
                None => { break; } // Connection closed by peer
                Some(request) => request,
            };

            // Did the client request Connection: Keep-Alive?
            let keep_alive = keep_alive_requested(&request);

            // Call request handler to get a Response
            let mut response = (&self.callback)(request);

            // Add necessary headers if missing
            if keep_alive {
                header_if_missing(&mut response, "Connection", "keep-alive");
                header_if_missing(&mut response, "Keep-Alive", "timeout=30, max=1000");
            }
            let len = format!("{}", response.body().len());
            header_if_missing(&mut response, "Content-Length", len.as_str());
            header_if_missing(&mut response, "Content-Type", "text/html; charset=utf-8");

            // Write responses back to stream
            println!("run() {:?}", response);
            if let Err(os_error) = send_response(response, &mut self.stream) {
                println!("run() send_response returned {}", os_error);
                break;
            }

            // Close connection unless client requested Connection: Keep-Alive
            if keep_alive == false { break; }

        }
        return self.stream.shutdown(Shutdown::Both);
    }


}


pub fn send_response<T: Buf, W: Write>(response: Response<T>, writer: &mut W) -> Result<(), std::io::Error> {
    let (parts, body) = response.into_parts();
    send_response_status(&parts.status, writer)?;
    send_response_headers(&parts.headers, writer)?;
    send_response_body(body, writer)?;
    return Ok(());
}


fn send_response_status<W: Write>(status: &StatusCode, writer: &mut W) -> Result<(), std::io::Error> {
    let status_line = format!("HTTP/1.1 {} {}\r\n", status.as_str(), status.canonical_reason().unwrap());
    writer.write(status_line.as_bytes())?;
    return Ok(());
}


fn send_response_headers<W: Write>(headers: &HeaderMap, writer: &mut W) -> Result<(), std::io::Error>{
    for (key, value) in headers.iter() {
        let key = String::from_utf8(pretty_case(key).into()).unwrap();
        let header_line = format!("{}: {}\r\n", key, value.to_str().unwrap());
        writer.write(header_line.as_bytes())?;
    }
    let empty_line = format!("\r\n");
    writer.write(empty_line.as_bytes())?;
    return Ok(());
}


fn send_response_body<T: Buf, W: Write>(body: T, writer: &mut W) -> Result<(), std::io::Error> {
    std::io::copy(&mut body.reader(), writer)?;
    return Ok(());
}



pub fn listener(bind_address: SocketAddr) -> Result<TcpListener, std::io::Error> {
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?;
    socket.set_only_v6(false)?;
    socket.bind(&bind_address.into())?;
    socket.listen(128)?;
    socket.set_reuse_address(true)?;
    return Ok(socket.into());
}


pub fn keep_alive_requested(request: &Request<Bytes>) -> bool {
    let key = HeaderName::from_bytes(b"connection".as_slice()).unwrap();
    return match request.headers().get(key) {
        None => false,
        Some(connection) => {
            if connection.as_bytes().to_ascii_lowercase().starts_with(b"keep-alive") { true }
            else { false }
        }
    }
}


pub fn read_request<R: BufRead>(reader: &mut R) -> Result<Option<Request<Bytes>>, StatusCode> {
    let mut req_builder = Request::builder();

    // Get request line, e.g. "HTTP/1.1 GET /index.html"
    let request_line = match read_line(reader) {
        Err(os_error) => {
            println!("read_request() read_line returned {}", os_error);
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok(line) => line,
    };

    // Connection closed by peer?
    if request_line.len() == 0 { return Ok(None); } 
    
    req_builder = parse_request_line(req_builder, &request_line)?;
    req_builder = read_request_headers(req_builder, reader)?;

    let body = read_request_body(&req_builder, reader)?;
    let request = finalize_request(req_builder, body)?;

    return Ok(Some(request));
}


fn request_content_length(req_builder: &ReqBuilder) -> Option<usize> {
    let key = "Content-Length";
    let opt_value = req_builder.headers_ref().unwrap().get(key);
    if let Some(value) = opt_value {
        if let Ok(length) = value.to_str().unwrap().parse::<usize>() {
            return Some(length);
        }
    }
    return None;
}


fn read_request_body<R: BufRead>(req_builder: &ReqBuilder, reader: &mut R) -> Result<Bytes, StatusCode> {
    let mut body = vec![];

    if let Some(bytes_to_read) = request_content_length(req_builder) {
        if bytes_to_read > 0 {
            body = vec![0u8; bytes_to_read];
            match reader.read_exact(&mut body) {
                Err(os_error) => {
                    println!("read_request_body() expected {} bytes, read_exact returned {}", bytes_to_read, os_error);
                    return Err(StatusCode::BAD_REQUEST);
                }
                Ok(()) => {}
            }
        }
    }

    return Ok(Bytes::from(body));
}


fn finalize_request<T>(req_builder: ReqBuilder, body: T) -> Result<Request<T>, StatusCode> {
    let request = match req_builder.body(body) {
        Ok(request) => request,
        Err(error) => {
            println!("finalize_request() ReqBuilder::body returned {}", error);
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    return Ok(request);
}


fn read_request_headers<R: BufRead>(mut req_builder: ReqBuilder, reader: &mut R) -> Result<ReqBuilder, StatusCode>{
    loop {
        // Read next HTTP header "Key: Value"
        let header_line = match read_line(reader) {
            Ok(line) => line,
            Err(os_error) => {
                println!("read_request_headers() read_line returned {}", os_error);
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        // Check for empty line (end of headers)
        if header_line.len() == 0 { break; }

        // Parse line into (HeaderName, HeaderValue) and add to Request
        let (key, value) = parse_header_line(&header_line)?;
        req_builder = req_builder.header(key, value); 

        // Sanity check; stop if we receive an unreasonably large header
        if req_builder.headers_ref().unwrap().len() > MAX_REQ_HEADER_COUNT {
            println!("read_request_headers() exceeded {} headers", MAX_REQ_HEADER_COUNT);
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    return Ok(req_builder);
}


fn parse_request_line(req_builder: ReqBuilder, request_line: &Bytes) -> Result<ReqBuilder, StatusCode> {
    if !request_line.is_ascii() { return Err(StatusCode::BAD_REQUEST); }
    let parts = split(&request_line, AsciiChar::Space.as_byte(), 3);

    // Verify we got three strings
    if parts.len() != 3 { 
        return Err(StatusCode::BAD_REQUEST); 
    }

    // The first one should be a valid HTTP Method
    let method = match Method::from_bytes(&parts[0]) {
        Err(_) => return Err(StatusCode::METHOD_NOT_ALLOWED),
        Ok(method) => method,
    };

    // Next is the URI, which can be more or less any contiguous ASCII imaginable
    let uri: http::uri::PathAndQuery = match std::str::from_utf8(&parts[1]) {
        Ok(str) => str.parse().unwrap(),
        Err(utf_error) => {
            // Should be impossible because we already verified the line is ASCII
            println!("parse_request_line() bad URI: {}", utf_error);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Last string must be HTTP/1.1
    // For now, anyway
    if parts[2].ne("HTTP/1.1") {
        return Err(StatusCode::HTTP_VERSION_NOT_SUPPORTED);
    }

    return Ok(req_builder.method(method).uri(uri).version(http::Version::HTTP_11));
}


fn parse_header_line(header_line: &Bytes) -> Result<(HeaderName, HeaderValue), StatusCode> {
    // Split in twain
    let parts = split(&header_line, AsciiChar::Space.as_byte(), 2);
    if parts.len() != 2 { return Err(StatusCode::BAD_REQUEST); }

    // First part is "Key:"
    let key = match parts[0].strip_suffix(&[AsciiChar::Colon.as_byte()]) {
        None => return Err(StatusCode::BAD_REQUEST),
        Some(bytes) => HeaderName::from_bytes(bytes),
    };

    // Second part is "Value"
    let value = HeaderValue::from_bytes(&parts[1]);

    // Return tuple if both are okay, otherwise signal error
    return match (key,value) {
        (Ok(key), Ok(value)) => Ok((key, value)),
        (_, _) => Err(StatusCode::BAD_REQUEST),
    }
}


// "content-type" -> "Content-Type" for readability and broken clients
fn pretty_case(key: &HeaderName) -> Bytes {
    let mut result = BytesMut::new();
    let mut initial = true;
    for byte in key.as_str().as_bytes() {
        let mut char = byte.clone();
        if initial { 
            char = char.to_ascii_uppercase(); 
            initial = false;
        }
        if char == AsciiChar::Minus.as_byte() {
            initial = true;
        }
        result.extend_from_slice(&[char]);
    }
    return result.into();
}


pub fn header_if_missing<T>(response: &mut Response<T>, key: &str, value: &str) {
    let key = HeaderName::from_bytes(key.as_bytes()).unwrap();
    let value = HeaderValue::from_bytes(value.as_bytes()).unwrap();
    if !response.headers().contains_key(&key) {
        response.headers_mut().append(key, value);
    }
}


fn read_line<R: BufRead>(reader: &mut R) -> Result<Bytes, std::io::Error> {
    let mut buffer = vec![];

    return match reader.take(MAX_LINE_LENGTH).read_until(AsciiChar::LineFeed.as_byte(), &mut buffer) {
        Ok(_) => {
            if buffer.ends_with(&[AsciiChar::LineFeed.as_byte()]) { buffer.pop(); }
            if buffer.ends_with(&[AsciiChar::CarriageReturn.as_byte()]) { buffer.pop(); } 
            Ok(Bytes::from(buffer))
        }
        Err(os_error) => Err(os_error),
    }
}


fn split(vector: &Bytes, split_char: u8, max_parts: usize) -> Vec<Bytes> {
    let mut parts = vec![BytesMut::from("")];
    for char in vector {
        if char == &split_char && parts.len() < max_parts {
            parts.push(BytesMut::from(""));
            continue;
        }
        parts.last_mut().unwrap().extend_from_slice(&[char.clone()]);
    }
    // Convert Vec<BytesMut> to Vec<Bytes>
    return parts.iter().map(|part| Bytes::from(part.clone())).collect::<Vec<_>>();
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(true, true);
    }
}
