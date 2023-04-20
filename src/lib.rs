
use std::io::prelude::*;
pub use bytes::Bytes;
use bytes::BytesMut;
use bytes::Buf;

const ASCII_NEWLINE: u8 = 0x0A;
const ASCII_RETURN: u8 = 0x0D;
const ASCII_COLON: u8 = b':';
const ASCII_SPACE: u8 = b' ';
const ASCII_DASH: u8 = b'-';

use http::HeaderName;
use http::HeaderValue;
use http::Method;
pub use http::{Request,Response,StatusCode};

pub struct Server {
    listener: std::net::TcpListener,
    callback: fn(std::net::TcpStream),
}


impl Server {

    pub fn new(bind_address: std::net::SocketAddr, connection_handler: fn(std::net::TcpStream)) -> Self {
        Server {
            listener: Server::socket(bind_address).into(),
            callback: connection_handler,
        }
    }

    fn socket(bind_address: std::net::SocketAddr) -> socket2::Socket {
        let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None).unwrap();
        // TODO: error checking
        let _ = socket.set_only_v6(false);
        let _ = socket.bind(&bind_address.into());
        let _ = socket.listen(128);
        let _ = socket.set_reuse_address(true);
        return socket;
    }

    pub fn run(&mut self) -> Result<(), std::io::Error> {
        for res in self.listener.incoming() {
            match res {
                Ok(stream) => (self.callback)(stream),
                Err(error) => return Err(error),
            }
        }
        return Err(std::io::Error::last_os_error());
    }

}


pub struct Connection {
    stream: std::net::TcpStream,
    callback: fn(http::Request<Bytes>)->http::Response<Bytes>,
}


impl Connection {

    pub fn new(stream: std::net::TcpStream, request_handler: fn(http::Request<Bytes>)->http::Response<Bytes>) -> Self {
        Connection {
            stream,
            callback: request_handler,
        }
    }


    pub fn run(&mut self) -> Result<(), std::io::Error> {
        let mut reader = std::io::BufReader::new(self.stream.try_clone().unwrap());
        loop {
            // read requests from stream

            let request_line = 
            match read_line(&mut reader) {
                Ok(line) => line,
                Err(error) => {
                    println!("read_line() {}", error);
                    break;
                }
            };

            match parse_request_line(&request_line) {
                Err(status) => { 
                    // TODO: generate error response
                    println!("parse_request_line() {}", status);
                    break; 
                } 
                Ok(mut req_builder) => {
                    // Now read the request headers
                    loop {
                        let header_line = read_line(&mut reader).unwrap();
                        println!("line={:?} len={}", header_line, header_line.len());
                        if header_line.len() == 0 { break; } // End of headers
                        match parse_header_line(&header_line) {
                            Err(status) => { 
                                // TODO: generate error response
                                println!("parse_header_line() {}", status);
                                break; 
                            } 
                            Ok((key,value)) => { 
                                req_builder = req_builder.header(key, value); 
                            }
                        }
                    }

                    // Read the request body, if any
                    // ...

                    let request = req_builder.body(Bytes::from("")).unwrap();

                    let keep_alive =
                    match request.headers().get(http::HeaderName::from_bytes(b"connection".as_slice()).unwrap()) {
                        None => false,
                        Some(connection) => {
                            if connection.as_bytes().starts_with(b"keep-alive") { true }
                            else { false }
                        }
                    };

                    // Call request handler
                    let mut response = (&self.callback)(request);

                    // Add necessary headers if missing
                    if keep_alive {
                        patch_response(&mut response, "Connection", "Keep-Alive");
                        patch_response(&mut response, "Keep-Alive", "timeout=30, max=1000");
                    }
                    let len = format!("{}", response.body().len());
                    patch_response(&mut response, "Content-Length", len.as_str());
                    patch_response(&mut response, "Content-Type", "text/html");

                    // Write responses back to stream
                    self.send_response(response);

                    // Close connection unless client requested Connection: Keep-Alive
                    if keep_alive == false { break; }
                }
            }
        }
        return self.stream.shutdown(std::net::Shutdown::Both);
    }


    fn send_response(&mut self, response: Response<Bytes>) {
        println!("response={:?}", response);
        let (parts, body) = response.into_parts();
    
        let status_line = format!("HTTP/1.1 {} {}\r\n", parts.status.as_str(), parts.status.canonical_reason().unwrap());
        println!("status_line={:?}", status_line);
        let _ = self.stream.write(status_line.as_bytes());
    
        for (key, value) in parts.headers.iter() {
            let key = String::from_utf8(pretty_case(key).into()).unwrap();
            let header_line = format!("{}: {}\r\n", key, value.to_str().unwrap());
            println!("header_line={:?}", header_line);
            let _ = self.stream.write(header_line.as_bytes());
        }
        let empty_line = format!("\r\n");
        let _ = self.stream.write(empty_line.as_bytes());
    
        println!("response body={:?}", body);
    
        let _ = std::io::copy(&mut body.reader(), &mut self.stream);
    }
    
}


fn parse_request_line(request_line: &Bytes) -> Result<http::request::Builder, StatusCode> {
    if !request_line.is_ascii() { return Err(StatusCode::BAD_REQUEST); }
    let parts = split(&request_line, ASCII_SPACE, 3);

    // Verify we got three strings
    if parts.len() != 3 { 
        return Err(StatusCode::BAD_REQUEST); 
    }

    // The first one should be a valid HTTP Method
    let method = 
    match Method::from_bytes(&parts[0]) {
        Err(_) => return Err(StatusCode::METHOD_NOT_ALLOWED),
        Ok(method) => method,
    };

    // Next is the URI, which can be more or less any contiguous ASCII imaginable
    let uri: http::uri::PathAndQuery =
    match std::str::from_utf8(&parts[1]) {
        Ok(str) => str.parse().unwrap(),
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    // Last string must be HTTP/1.1
    // For now, anyway
    if parts[2].ne("HTTP/1.1") {
        return Err(StatusCode::HTTP_VERSION_NOT_SUPPORTED);
    }

    let request = Request::builder()
        .method(method)
        .uri(uri)
        .version(http::Version::HTTP_11);

    return Ok(request);
}


fn parse_header_line(header_line: &Bytes) -> Result<(HeaderName, HeaderValue), StatusCode> {
    let parts = split(&header_line, ASCII_SPACE, 2);
    if parts.len() != 2 { return Err(StatusCode::BAD_REQUEST); }
    let key = match parts[0].strip_suffix(&[ASCII_COLON]) {
        None => return Err(StatusCode::BAD_REQUEST),
        Some(bytes) => HeaderName::from_bytes(bytes),
    };
    let value = HeaderValue::from_bytes(&parts[1]);
    return match (key,value) {
        (Ok(key), Ok(value)) => Ok((key, value)),
        (_, _) => Err(StatusCode::BAD_REQUEST),
    }
}


fn pretty_case(key: &HeaderName) -> Bytes {
    let mut result = BytesMut::new();
    let mut initial = true;
    for byte in key.as_str().as_bytes() {
        let mut char = byte.clone();
        if initial { 
            char = char.to_ascii_uppercase(); 
            initial = false;
        }
        if char == ASCII_DASH {
            initial = true;
        }
        result.extend_from_slice(&[char]);
    }
    return result.into();
}


fn patch_response(response: &mut Response<Bytes>, key: &str, value: &str) {
    let key = HeaderName::from_bytes(key.as_bytes()).unwrap();
    let value = HeaderValue::from_bytes(value.as_bytes()).unwrap();
    if !response.headers().contains_key(&key) {
        response.headers_mut().append(key, value);
    }
}


fn read_line(reader: &mut std::io::BufReader<std::net::TcpStream>) -> Result<Bytes,String> {
    let mut buffer = vec![];
    // TODO: read_until() blocks and allocates an arbitrarily large buffer,
    // allowing an attacker to crash the server by sending an oversized line.
    // Replace with something that enforces a reasonable limit.
    return match reader.read_until(ASCII_NEWLINE, &mut buffer) {
        Ok(_) => {
            if buffer.ends_with(&[ASCII_NEWLINE]) { buffer.pop(); }
            if buffer.ends_with(&[ASCII_RETURN]) { buffer.pop(); }
            Ok(Bytes::from(buffer))
        }
        Err(msg) => Err(format!("{}", msg)),
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
